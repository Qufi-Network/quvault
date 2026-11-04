// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title PalmWallet
 * @notice A wallet that Ethereum itself will not move without a palm.
 *
 * Every payment needs signatures from enough of the wallet's signers AND from the palm key. The
 * palm key is held by Palm's palm signer, which signs only after checking Veyns' own signed
 * palm approvals for that exact payment. So a stolen recovery phrase, or a stolen signer key,
 * is not enough: without a palm approval there is no palm signature, and this contract refuses.
 *
 * If the palm signer is ever gone, the signers alone can still reach the funds, but only by
 * scheduling a payment that runs after `recoveryDelay`. During that wait the palm path can
 * cancel it, so a thief who schedules one is seen (Palm alerts every signer) and stopped.
 *
 * Deliberately narrow: plain transfers only, native coin or ERC-20 `transfer`. No arbitrary
 * calls, no delegatecall, no upgrades, no owner changes; a different set of signers is a new
 * wallet. Signatures are EIP-712, bound to this wallet, this chain and a one-time nonce.
 */
contract PalmWallet is EIP712 {
    bytes32 private constant TRANSFER_TYPEHASH =
        keccak256("Transfer(address token,address to,uint256 amount,uint256 nonce)");
    bytes32 private constant RECOVERY_TYPEHASH =
        keccak256("Recovery(address token,address to,uint256 amount,uint256 nonce)");
    bytes32 private constant CANCEL_TYPEHASH = keccak256("Cancel(bytes32 id,uint256 nonce)");

    /// The native coin, in the `token` slot.
    address public constant NATIVE = address(0);

    uint256 public constant MAX_SIGNERS = 20;
    uint256 public constant MIN_RECOVERY_DELAY = 1 hours;
    uint256 public constant MAX_RECOVERY_DELAY = 730 days;

    address public immutable palmSigner;
    uint256 public immutable threshold;
    uint256 public immutable recoveryDelay;
    address[] private _signers;
    mapping(address => bool) public isSigner;

    /// Every signed action uses the next nonce, once.
    uint256 public nonce;

    struct Scheduled {
        address token;
        address to;
        uint256 amount;
        uint64 runsAt;
    }
    mapping(bytes32 => Scheduled) public scheduled;

    event Transferred(uint256 indexed nonce, address indexed token, address indexed to, uint256 amount);
    event RecoveryScheduled(bytes32 indexed id, address indexed token, address indexed to, uint256 amount, uint256 runsAt);
    event RecoveryCancelled(bytes32 indexed id);
    event RecoveryExecuted(bytes32 indexed id);
    event Received(address indexed from, uint256 amount);

    error NoPalm();
    error NotEnoughSigners();
    error NotADistinctSigner();
    error NothingScheduled();
    error TooEarly(uint256 runsAt);
    error TransferFailed();
    error BadSetup(string reason);

    constructor(address[] memory signers_, uint256 threshold_, address palmSigner_, uint256 recoveryDelay_)
        EIP712("PalmWallet", "1")
    {
        uint256 count = signers_.length;
        if (count == 0 || count > MAX_SIGNERS) revert BadSetup("between 1 and 20 signers");
        if (threshold_ == 0 || threshold_ > count) revert BadSetup("threshold out of range");
        // A shared wallet is never spent by one signature, even with the palm.
        if (count > 1 && threshold_ < 2) revert BadSetup("a shared wallet needs at least two signatures");
        if (palmSigner_ == address(0)) revert BadSetup("no palm signer");
        if (recoveryDelay_ < MIN_RECOVERY_DELAY || recoveryDelay_ > MAX_RECOVERY_DELAY) revert BadSetup("recovery delay out of range");

        address previous;
        for (uint256 i; i < count; ++i) {
            address signer = signers_[i];
            // Sorted ascending: no zero address, no duplicates, one canonical order.
            if (signer <= previous) revert BadSetup("signers must be sorted and distinct");
            if (signer == palmSigner_) revert BadSetup("the palm signer cannot also be a signer");
            isSigner[signer] = true;
            _signers.push(signer);
            previous = signer;
        }
        threshold = threshold_;
        palmSigner = palmSigner_;
        recoveryDelay = recoveryDelay_;
    }

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    function signers() external view returns (address[] memory) {
        return _signers;
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /* ------------------------------------------------------------ the normal path */

    /// The digest the signers and the palm key sign for a transfer at `nonce_`.
    function transferDigest(address token, address to, uint256 amount, uint256 nonce_) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(TRANSFER_TYPEHASH, token, to, amount, nonce_)));
    }

    /**
     * Sends `amount` of `token` (NATIVE for the coin) to `to`. Anyone may submit it, because the
     * signatures are the authority: `signerSignatures` from distinct signers, in ascending order
     * of signer address, at least `threshold` of them, and `palmSignature` from the palm key.
     */
    function transfer(
        address token,
        address to,
        uint256 amount,
        bytes[] calldata signerSignatures,
        bytes calldata palmSignature
    ) external {
        uint256 used = nonce;
        bytes32 digest = transferDigest(token, to, amount, used);
        if (ECDSA.recover(digest, palmSignature) != palmSigner) revert NoPalm();
        _checkSigners(digest, signerSignatures);
        nonce = used + 1;
        _send(token, to, amount);
        emit Transferred(used, token, to, amount);
    }

    /* ----------------------------------------------------------- the recovery path */

    function recoveryDigest(address token, address to, uint256 amount, uint256 nonce_) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(RECOVERY_TYPEHASH, token, to, amount, nonce_)));
    }

    function cancelDigest(bytes32 id, uint256 nonce_) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(CANCEL_TYPEHASH, id, nonce_)));
    }

    /// The signers alone schedule a transfer; it can run only after `recoveryDelay`.
    function scheduleRecovery(address token, address to, uint256 amount, bytes[] calldata signerSignatures)
        external
        returns (bytes32 id)
    {
        uint256 used = nonce;
        _checkSigners(recoveryDigest(token, to, amount, used), signerSignatures);
        nonce = used + 1;
        id = keccak256(abi.encode(token, to, amount, used));
        uint64 runsAt = uint64(block.timestamp + recoveryDelay);
        scheduled[id] = Scheduled(token, to, amount, runsAt);
        emit RecoveryScheduled(id, token, to, amount, runsAt);
    }

    /// Runs a scheduled transfer once its delay has passed. Anyone may submit it.
    function executeRecovery(bytes32 id) external {
        Scheduled memory s = scheduled[id];
        if (s.runsAt == 0) revert NothingScheduled();
        if (block.timestamp < s.runsAt) revert TooEarly(s.runsAt);
        delete scheduled[id];
        _send(s.token, s.to, s.amount);
        emit RecoveryExecuted(id);
    }

    /// The palm path stops a scheduled transfer: the palm key's signature is enough to cancel.
    function cancelRecovery(bytes32 id, bytes calldata palmSignature) external {
        if (scheduled[id].runsAt == 0) revert NothingScheduled();
        uint256 used = nonce;
        if (ECDSA.recover(cancelDigest(id, used), palmSignature) != palmSigner) revert NoPalm();
        nonce = used + 1;
        delete scheduled[id];
        emit RecoveryCancelled(id);
    }

    /* ---------------------------------------------------------------- internals */

    function _checkSigners(bytes32 digest, bytes[] calldata signatures) private view {
        if (signatures.length < threshold) revert NotEnoughSigners();
        address previous;
        for (uint256 i; i < signatures.length; ++i) {
            address signer = ECDSA.recover(digest, signatures[i]);
            // Ascending order makes every signature come from a different signer.
            if (signer <= previous || !isSigner[signer]) revert NotADistinctSigner();
            previous = signer;
        }
    }

    function _send(address token, address to, uint256 amount) private {
        if (token == NATIVE) {
            (bool ok,) = to.call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            // ERC-20 transfer, accepting tokens that return nothing as well as those returning true.
            (bool ok, bytes memory out) = token.call(abi.encodeWithSelector(0xa9059cbb, to, amount));
            if (!ok || (out.length != 0 && !abi.decode(out, (bool)))) revert TransferFailed();
        }
    }
}

/// Deploys Palm Wallets at addresses known before they exist, so a wallet can receive first.
contract PalmWalletFactory {
    event Created(address indexed wallet, address indexed palmSigner, uint256 threshold);

    function create(address[] calldata signers, uint256 threshold, address palmSigner, uint256 recoveryDelay, bytes32 salt)
        external
        returns (PalmWallet wallet)
    {
        wallet = new PalmWallet{salt: salt}(signers, threshold, palmSigner, recoveryDelay);
        emit Created(address(wallet), palmSigner, threshold);
    }

    function addressOf(address[] calldata signers, uint256 threshold, address palmSigner, uint256 recoveryDelay, bytes32 salt)
        external
        view
        returns (address)
    {
        bytes memory init = abi.encodePacked(
            type(PalmWallet).creationCode, abi.encode(signers, threshold, palmSigner, recoveryDelay)
        );
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(init))))));
    }
}
