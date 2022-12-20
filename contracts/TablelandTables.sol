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
    // A mapping of table ids to table controller addresses.
    mapping(uint256 => address) internal _controllers;
    // A mapping of table controller addresses to lock status.
    mapping(uint256 => bool) internal _locks;
    // The maximum size allowed for a query.
    uint256 internal constant QUERY_MAX_SIZE = 35000;
    // The maximum number of sql statements that can be run in a single call to runSQLs
    // TODO: does having a limit here make sense, and if so what should it be?
    uint256 internal constant RUNNABLES_MAX_LENGTH = 10;

    function initialize(
        string memory baseURI
    ) public initializerERC721A initializer {
        __ERC721A_init("Tableland Tables", "TABLE");
        __ERC721AQueryable_init();
        __Ownable_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        _baseURIString = baseURI;
    }

    /**
     * @dev See {ITablelandTables-runSQL}.
     */
    function runSQL(
        address owner,
        string calldata statement
    ) external payable override whenNotPaused returns (uint256) {
        return _createTable(owner, statement);
    }

    /**
     * @dev See {ITablelandTables-runSQL}.
     */
    function runSQL(
        address caller,
        uint256 tableId,
        string calldata statement
    ) external payable override whenNotPaused nonReentrant {
        _mutateTable(caller, tableId, statement);
    }

    /**
     * @dev See {ITablelandTables-runSQL}.
     */
    function runSQL(
        address caller,
        ITablelandTables.Runnable[] calldata runnables
    ) external payable override whenNotPaused nonReentrant {
        if (runnables.length > RUNNABLES_MAX_LENGTH) {
            revert MaxStatementCountExceeded(
                runnables.length,
                RUNNABLES_MAX_LENGTH
            );
        }

        for (uint256 i = 0; i < runnables.length; i++) {
            if (runnables[i].tableId > 0) {
                // simple pass along of each set of runSQL calls
                _mutateTable(
                    caller,
                    runnables[i].tableId,
                    runnables[i].statement
                );
            } else {
                // if the tableId isn't greater than the default of 0 then the
                // statement must be a create statement, and we pass it through
                _createTable(caller, runnables[i].statement);
            }
        }
    }

    function _createTable(
        address owner,
        string calldata statement
    ) private returns (uint256 tableId) {
        tableId = _nextTokenId();
        _safeMint(owner, 1);

        emit CreateTable(owner, tableId, statement);

        return tableId;
    }

    function _mutateTable(
        address caller,
        uint256 tableId,
        string calldata statement
    ) private {
        if (
            !_exists(tableId) ||
            !(caller == _msgSenderERC721A() || owner() == _msgSenderERC721A())
        ) {
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
     * @dev Returns an {ITablelandController.Policy} for `caller` and `tableId`.
     *
     * An allow-all policy is returned if the table's controller does not exist.
     *
     * Requirements:
     *
     * - if the controller is an EOA, caller must be controller
     * - if the controller is a contract address, it must implement {ITablelandController}
     */
    function _getPolicy(
        address caller,
        uint256 tableId
    ) private returns (ITablelandController.Policy memory) {
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
            !(caller == _msgSenderERC721A() ||
                owner() == _msgSenderERC721A()) ||
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
    function getController(
        uint256 tableId
    ) external view override returns (address) {
        return _controllers[tableId];
    }

    /**
     * @dev See {ITablelandTables-lockController}.
     */
    function lockController(
        address caller,
        uint256 tableId
    ) external override whenNotPaused {
        if (
            caller != ownerOf(tableId) ||
            !(caller == _msgSenderERC721A() ||
                owner() == _msgSenderERC721A()) ||
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
            // quantity is only > 1 after bulk minting when from == address(0)
            emit TransferTable(from, to, startTokenId);
        }
    }

    /**
     * @dev See {UUPSUpgradeable-_authorizeUpgrade}.
     */
    function _authorizeUpgrade(address) internal view override onlyOwner {} // solhint-disable no-empty-blocks
}
