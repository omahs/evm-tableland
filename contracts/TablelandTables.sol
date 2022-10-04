// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "erc721a-upgradeable/contracts/ERC721AUpgradeable.sol";
import "erc721a-upgradeable/contracts/extensions/ERC721AQueryableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";
import "./ITablelandTables.sol";
import "./ITablelandController.sol";

/**
 * @dev Implementation of {ITablelandTables}.
 */
contract TablelandTables is
    ITablelandTables,
    ERC721AUpgradeable,
    ERC721AQueryableUpgradeable,
    OwnableUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
    // A URI used to reference off-chain table metadata.
    string internal _baseURIString;

    // Mapping from table ID to approved address.
    mapping(uint256 => address) internal _tableRelayApprovals;
    // Mapping from owner to relayer approvals
    mapping(address => mapping(address => bool)) internal _relayerApprovals;

    // A mapping of table ids to table controller addresses.
    mapping(uint256 => address) internal _controllers;
    // A mapping of table controller addresses to lock status.
    mapping(uint256 => bool) internal _locks;
    // The maximum size allowed for a query.
    uint256 internal constant QUERY_MAX_SIZE = 35000;

    function initialize(string memory baseURI)
        public
        initializerERC721A
        initializer
    {
        __ERC721A_init("Tableland Tables", "TABLE");
        __ERC721AQueryable_init();
        __Ownable_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        _baseURIString = baseURI;
    }

    /**
     * @dev See {ITablelandTables-createTable}.
     */
    function createTable(address owner, string memory statement)
        external
        payable
        override
        whenNotPaused
        returns (uint256 tableId)
    {
        tableId = _nextTokenId();
        _safeMint(owner, 1);

        emit CreateTable(owner, tableId, statement);

        return tableId;
    }

    /**
     * @dev See {ITablelandTables-runSQL}.
     */
    function runSQL(
        address caller,
        uint256 tableId,
        string memory statement
    ) external payable override whenNotPaused nonReentrant {
        if (!_exists(tableId) || !(_isRelayerOrCaller(caller, tableId))) {
            revert Unauthorized();
        }

        uint256 querySize = bytes(statement).length;
        if (querySize > QUERY_MAX_SIZE) {
            revert MaxQuerySizeExceeded(querySize, QUERY_MAX_SIZE);
        }

        emit RunSQL(
            caller,
            ownerOf(tableId) == caller,
            tableId,
            statement,
            _getPolicy(caller, tableId)
        );
    }

    /**
     * @dev Gives permission to `to` to call runSQL and setController for `tableId` token
     * TODO: The approval is cleared when the table is transferred.
     *
     * Only a single account per table can be approved at a time, so approving the
     * zero address clears previous approvals.
     *
     * Requirements:
     *
     * - The caller must own the table.
     * - `tableId` must exist.
     *
     * TODO: Emits an {RelayApproval} event.
     */
    function approveRelayer(address to, uint256 tableId)
        public
        override
        whenNotPaused
    {
        address owner = ownerOf(tableId);

        if (_msgSenderERC721A() != owner) {
            revert Unauthorized();
        }

        _tableRelayApprovals[tableId] = to;
        //TODO: emit RelayApproval(owner, to, tableId);
    }

    /**
     * @dev Returns the account approved to relay for `tableId` table.
     *
     * Requirements:
     *
     * - `tableId` must exist.
     */
    function getRelayer(uint256 tableId)
        public
        view
        override
        returns (address)
    {
        if (!_exists(tableId)) revert Unauthorized();

        return _tableRelayApprovals[tableId];
    }

    /**
     * @dev Approve or remove `relayer` as a relayer for the caller.
     * Relayers can call {runSQL} or {setController}
     * with the access rights of the table owner.
     *
     * Requirements:
     *
     * - The `relayer` cannot be the caller.
     *
     * TODO: Emits an {ApprovalForAll} event.
     */
    function setRelayerForAll(address relayer, bool approved)
        public
        override
        whenNotPaused
    {
        if (relayer == _msgSenderERC721A()) revert Unauthorized();

        _relayerApprovals[_msgSenderERC721A()][relayer] = approved;
        // TODO: emit ApprovalForAll(_msgSenderERC721A(), relayer, approved);
    }

    /**
     * @dev Returns if the `relayer` has access rights over all of `owner`'s tables.
     *
     * See {setRelayerForAll}.
     */
    function isRelayerForAll(address owner, address relayer)
        public
        view
        override
        returns (bool)
    {
        return _relayerApprovals[owner][relayer];
    }

    function _isRelayerOrCaller(address caller, uint256 tableId)
        private
        view
        returns (bool result)
    {
        if (caller == _msgSenderERC721A()) return true;
        if (_relayerApprovals[caller][_msgSenderERC721A()]) return true;
        if (_tableRelayApprovals[tableId] == _msgSenderERC721A()) return true;

        return false;
    }

    /**
     * @dev Returns an {ITablelandController.Policy} for `caller` and `tableId`.
     *
     * An allow-all policy is returned if the table's controller does not exist.
     *
     * Requirements:
     *
     * - if the controller is an EOA, caller must be controller
     * - if the controller is a contract address, it must implement {ITablelandController}
     */
    function _getPolicy(address caller, uint256 tableId)
        private
        returns (ITablelandController.Policy memory)
    {
        address controller = _controllers[tableId];
        if (_isContract(controller)) {
            return
                ITablelandController(controller).getPolicy{value: msg.value}(
                    caller
                );
        }
        if (!(controller == address(0) || controller == caller)) {
            revert Unauthorized();
        }

        return
            ITablelandController.Policy({
                allowInsert: true,
                allowUpdate: true,
                allowDelete: true,
                whereClause: "",
                withCheck: "",
                updatableColumns: new string[](0)
            });
    }

    /**
     * @dev Returns whether or not `account` is a contract address.
     */
    function _isContract(address account) private view returns (bool) {
        return account.code.length > 0;
    }

    /**
     * @dev See {ITablelandTables-setController}.
     */
    function setController(
        address caller,
        uint256 tableId,
        address controller
    ) external override whenNotPaused {
        if (
            caller != ownerOf(tableId) ||
            !(_isRelayerOrCaller(caller, tableId)) ||
            _locks[tableId]
        ) {
            revert Unauthorized();
        }

        _controllers[tableId] = controller;

        emit SetController(tableId, controller);
    }

    /**
     * @dev See {ITablelandTables-getController}.
     */
    function getController(uint256 tableId)
        external
        view
        override
        returns (address)
    {
        return _controllers[tableId];
    }

    /**
     * @dev See {ITablelandTables-lockController}.
     */
    function lockController(address caller, uint256 tableId)
        external
        override
        whenNotPaused
    {
        if (
            caller != ownerOf(tableId) ||
            !(_isRelayerOrCaller(caller, tableId)) ||
            _locks[tableId]
        ) {
            revert Unauthorized();
        }

        _locks[tableId] = true;
    }

    /**
     * @dev See {ITablelandTables-setBaseURI}.
     */
    function setBaseURI(string memory baseURI) external override onlyOwner {
        _baseURIString = baseURI;
    }

    /**
     * @dev See {ERC721AUpgradeable-_baseURI}.
     */
    function _baseURI() internal view override returns (string memory) {
        return _baseURIString;
    }

    /**
     * @dev See {ITablelandTables-pause}.
     */
    function pause() external override onlyOwner {
        _pause();
    }

    /**
     * @dev See {ITablelandTables-unpause}.
     */
    function unpause() external override onlyOwner {
        _unpause();
    }

    /**
     * @dev See {ERC721AUpgradeable-_startTokenId}.
     */
    function _startTokenId() internal pure override returns (uint256) {
        return 1;
    }

    /**
     * @dev See {ERC721AUpgradeable-_afterTokenTransfers}.
     */
    function _afterTokenTransfers(
        address from,
        address to,
        uint256 startTokenId,
        uint256 quantity
    ) internal override {
        super._afterTokenTransfers(from, to, startTokenId, quantity);
        if (from != address(0)) {
            _tableRelayApprovals[startTokenId] = address(0);
            // quantity is only > 1 after bulk minting when from == address(0)
            emit TransferTable(from, to, startTokenId);
        }
    }

    /**
     * @dev See {UUPSUpgradeable-_authorizeUpgrade}.
     */
    function _authorizeUpgrade(address) internal view override onlyOwner {} // solhint-disable no-empty-blocks
}
