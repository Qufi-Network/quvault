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
 * palm approvals for that exact payment. So a stolen recovery phrase, or a stolen signer key, is
 * not enough: without a palm approval there is no palm signature, and this contract refuses.
 *
 * The recovery path works the way a Bitcoin palm vault's does. If the palm has approved nothing
 * here for `recoveryDelay`, the signers alone can move the coins; any palm approved payment or
 * refresh starts that wait again. Nobody can start the clock but time, so a thief with the
 * recovery phrase has nothing to schedule, nothing to front run and nothing to win but waiting
 * out an owner who keeps refreshing; and the palm key alone has no function here at all, so a
 * stolen palm key can neither move the coins nor keep the signers out.
 *
 * Every palm approved payment may carry Palm's fee, paid in the same asset to `feeTo`, which the
 * contract caps at 0.1% of the amount whatever the signatures say, and a refund of the network
 * fee in the native coin to whoever submitted it. Both are in what the signers and the palm sign.
 *
 * Deliberately narrow: plain transfers only, native coin or ERC-20 `transfer`. No arbitrary
 * calls, no delegatecall, no upgrades, no owner changes; a different set of signers is a new
 * wallet. Signatures are EIP-712, bound to this wallet, this chain, a one time nonce and a
 * deadline after which they are worthless.
 */
contract PalmWallet is EIP712 {
    bytes32 private constant TRANSFER_TYPEHASH = keccak256(
        "Transfer(address token,address to,uint256 amount,uint256 fee,address feeTo,uint256 gasRefund,uint256 deadline,uint256 nonce)"
    );
    bytes32 private constant REFRESH_TYPEHASH = keccak256("Refresh(uint256 gasRefund,uint256 deadline,uint256 nonce)");
    bytes32 private constant RECOVERY_TYPEHASH =
        keccak256("Recovery(address token,address to,uint256 amount,uint256 deadline,uint256 nonce)");

    /// The native coin, in the `token` slot.
    address public constant NATIVE = address(0);

    uint256 public constant MAX_SIGNERS = 20;
    uint256 public constant MIN_RECOVERY_DELAY = 1 hours;
    uint256 public constant MAX_RECOVERY_DELAY = 730 days;
    /// Palm's fee is at most amount / 1000, which is 0.1%, whatever anyone signs.
    uint256 public constant FEE_DIVISOR = 1000;

    address public immutable palmSigner;
    uint256 public immutable threshold;
    uint256 public immutable recoveryDelay;
    address[] private _signers;
    mapping(address => bool) public isSigner;

    /// Every signed action uses the next nonce, once.
    uint256 public nonce;
    /// When the palm last approved something here. The recovery path opens `recoveryDelay` after.
    uint256 public lastActivity;

    /// One payment, as the signers and the palm approve it.
    struct Payment {
        address token;
        address to;
        uint256 amount;
        uint256 fee;
        address feeTo;
        uint256 gasRefund;
        uint256 deadline;
    }

    event Transferred(uint256 indexed nonce, address indexed token, address indexed to, uint256 amount, uint256 fee, uint256 gasRefund);
    event Refreshed(uint256 indexed nonce, uint256 gasRefund);
    event Recovered(uint256 indexed nonce, address indexed token, address indexed to, uint256 amount);
    event Received(address indexed from, uint256 amount);

    error NoPalm();
    error NotEnoughSigners();
    error NotADistinctSigner();
    error Expired();
    error FeeTooHigh();
    error NoFeeRecipient();
    error NotYetDormant(uint256 opensAt);
    error NotAToken();
    error TransferFailed();
    error BadSetup(string reason);

    constructor(address[] memory signers_, uint256 threshold_, address palmSigner_, uint256 recoveryDelay_)
        EIP712("PalmWallet", "2")
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
        lastActivity = block.timestamp;
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

    /// When the signers alone could first move the coins, if the palm approves nothing before then.
    function recoveryOpensAt() public view returns (uint256) {
        return lastActivity + recoveryDelay;
    }

    /* ------------------------------------------------------------ the palm path */

    /// The digest the signers and the palm key sign for a payment at `nonce_`.
    function transferDigest(Payment calldata p, uint256 nonce_) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(
            TRANSFER_TYPEHASH, p.token, p.to, p.amount, p.fee, p.feeTo, p.gasRefund, p.deadline, nonce_
        )));
    }

    /**
     * Pays `amount` of `token` (NATIVE for the coin) to `to`, Palm's `fee` in the same asset to
     * `feeTo`, and `gasRefund` of the native coin to whoever submits it. Anyone may submit,
     * because the signatures are the authority: `signerSignatures` from distinct signers, in
     * ascending order of signer address, at least `threshold` of them, and `palmSignature` from
     * the palm key, all over the same digest, before `deadline`.
     */
    function transfer(Payment calldata p, bytes[] calldata signerSignatures, bytes calldata palmSignature) external {
        if (block.timestamp > p.deadline) revert Expired();
        if (p.fee > p.amount / FEE_DIVISOR) revert FeeTooHigh();
        if (p.fee != 0 && p.feeTo == address(0)) revert NoFeeRecipient();
        uint256 used = nonce;
        bytes32 digest = transferDigest(p, used);
        if (ECDSA.recover(digest, palmSignature) != palmSigner) revert NoPalm();
        _checkSigners(digest, signerSignatures);
        nonce = used + 1;
        lastActivity = block.timestamp;
        _send(p.token, p.to, p.amount);
        if (p.fee != 0) _send(p.token, p.feeTo, p.fee);
        if (p.gasRefund != 0) _send(NATIVE, msg.sender, p.gasRefund);
        emit Transferred(used, p.token, p.to, p.amount, p.fee, p.gasRefund);
    }

    function refreshDigest(uint256 gasRefund, uint256 deadline, uint256 nonce_) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(REFRESH_TYPEHASH, gasRefund, deadline, nonce_)));
    }

    /// Moves nothing: the signers and the palm say they are here, and the recovery path closes again.
    function refresh(uint256 gasRefund, uint256 deadline, bytes[] calldata signerSignatures, bytes calldata palmSignature) external {
        if (block.timestamp > deadline) revert Expired();
        uint256 used = nonce;
        bytes32 digest = refreshDigest(gasRefund, deadline, used);
        if (ECDSA.recover(digest, palmSignature) != palmSigner) revert NoPalm();
        _checkSigners(digest, signerSignatures);
        nonce = used + 1;
        lastActivity = block.timestamp;
        if (gasRefund != 0) _send(NATIVE, msg.sender, gasRefund);
        emit Refreshed(used, gasRefund);
    }

    /* ----------------------------------------------------------- the recovery path */

    function recoveryDigest(address token, address to, uint256 amount, uint256 deadline, uint256 nonce_)
        public
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(keccak256(abi.encode(RECOVERY_TYPEHASH, token, to, amount, deadline, nonce_)));
    }

    /**
     * The signers alone, without the palm, once the palm has approved nothing here for
     * `recoveryDelay`. It does not reset the clock, so heirs can make as many as they need.
     * Before the path opens it changes nothing, not even the nonce, so a thief holding the
     * signers' keys cannot touch anything a palm approval depends on.
     */
    function recover(address token, address to, uint256 amount, uint256 deadline, bytes[] calldata signerSignatures) external {
        uint256 opensAt = recoveryOpensAt();
        if (block.timestamp < opensAt) revert NotYetDormant(opensAt);
        if (block.timestamp > deadline) revert Expired();
        uint256 used = nonce;
        _checkSigners(recoveryDigest(token, to, amount, deadline, used), signerSignatures);
        nonce = used + 1;
        _send(token, to, amount);
        emit Recovered(used, token, to, amount);
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
            // A token must be a contract: a call to an empty address "succeeds" and moves nothing.
            if (token.code.length == 0) revert NotAToken();
            // ERC-20 transfer, accepting tokens that return nothing as well as those returning true.
            (bool ok, bytes memory out) = token.call(abi.encodeWithSelector(0xa9059cbb, to, amount));
            if (!ok || (out.length != 0 && !abi.decode(out, (bool)))) revert TransferFailed();
        }
    }
}
