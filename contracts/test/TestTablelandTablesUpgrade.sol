// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "erc721a-upgradeable/contracts/ERC721AUpgradeable.sol";
import "erc721a-upgradeable/contracts/extensions/ERC721AQueryableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "../ITablelandTables.sol";
import "../ITablelandController.sol";

contract TestTablelandTablesUpgrade is
    ITablelandTables,
    ERC721AUpgradeable,
    ERC721AQueryableUpgradeable,
    OwnableUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
    string internal _baseURIString;
    mapping(uint256 => address) internal _tableRelayApprovals;
    mapping(address => mapping(address => bool)) internal _relayerApprovals;
    mapping(uint256 => address) internal _controllers;
    mapping(uint256 => bool) internal _locks;
    uint256 internal constant QUERY_MAX_SIZE = 35000;

    mapping(uint256 => address) private _dummyStorage;

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

    function createTable(address, string memory)
        external
        payable
        override
        whenNotPaused
        returns (uint256)
    {} // solhint-disable no-empty-blocks

    function runSQL(
        address caller,
        uint256 tableId,
        string memory statement
    ) external payable override whenNotPaused nonReentrant {
        if (
            !_exists(tableId) ||
            !(caller == _msgSenderERC721A() || owner() == _msgSenderERC721A())
        ) {
            revert Unauthorized();
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

    function _isContract(address account) private view returns (bool) {
        return account.code.length > 0;
    }

    function setController(
        address,
        uint256,
        address
    ) external override whenNotPaused {} // solhint-disable no-empty-blocks

    function getController(uint256 tableId)
        external
        view
        override
        returns (address)
    {} // solhint-disable no-empty-blocks

    function lockController(address caller, uint256 tableId)
        external
        override
        whenNotPaused
    {} // solhint-disable no-empty-blocks

    // solhint-disable-next-line no-empty-blocks
    function setBaseURI(string memory) external override onlyOwner {}

    // solhint-disable-next-line no-empty-blocks
    function _baseURI() internal view override returns (string memory) {}

    // solhint-disable-next-line no-empty-blocks
    function pause() external override onlyOwner {}

    // solhint-disable-next-line no-empty-blocks
    function unpause() external override onlyOwner {}

    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address) internal view override onlyOwner {}
}
