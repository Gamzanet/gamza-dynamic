// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {IHooks} from "../../src/interfaces/IHooks.sol";
import {Hooks} from "../../src/libraries/Hooks.sol";
import {IPoolManager} from "../../src/interfaces/IPoolManager.sol";
import {IProtocolFees} from "../../src/interfaces/IProtocolFees.sol";
import {IProtocolFeeController} from "../../src/interfaces/IProtocolFeeController.sol";
import {PoolManager} from "../../src/PoolManager.sol";
import {TickMath} from "../../src/libraries/TickMath.sol";
import {Pool} from "../../src/libraries/Pool.sol";
import {Deployers} from "../utils/Deployers.sol";
import {Currency, CurrencyLibrary} from "../../src/types/Currency.sol";
import {MockHooks} from "../../src/test/MockHooks.sol";
import {MockContract} from "../../src/test/MockContract.sol";
import {EmptyTestHooks} from "../../src/test/EmptyTestHooks.sol";
import {PoolKey} from "../../src/types/PoolKey.sol";
import {PoolModifyLiquidityTest} from "../../src/test/PoolModifyLiquidityTest.sol";
import {BalanceDelta, BalanceDeltaLibrary} from "../../src/types/BalanceDelta.sol";
import {PoolSwapTest} from "../../src/test/PoolSwapTest.sol";
import {TestInvalidERC20} from "../../src/test/TestInvalidERC20.sol";
import {GasSnapshot} from "forge-gas-snapshot/GasSnapshot.sol";
import {PoolEmptyUnlockTest} from "../../src/test/PoolEmptyUnlockTest.sol";
import {Action} from "../../src/test/PoolNestedActionsTest.sol";
import {PoolId} from "../../src/types/PoolId.sol";
import {LPFeeLibrary} from "../../src/libraries/LPFeeLibrary.sol";
import {Position} from "../../src/libraries/Position.sol";
import {Constants} from "../utils/Constants.sol";
import {SafeCast} from "../../src/libraries/SafeCast.sol";
import {AmountHelpers} from "../utils/AmountHelpers.sol";
import {ProtocolFeeLibrary} from "../../src/libraries/ProtocolFeeLibrary.sol";
import {IProtocolFees} from "../../src/interfaces/IProtocolFees.sol";
import {StateLibrary} from "../../src/libraries/StateLibrary.sol";
import {Actions} from "../../src/test/ActionsRouter.sol";

contract PoolManagerTest is Test, Deployers, GasSnapshot {
    using Hooks for IHooks;
    using LPFeeLibrary for uint24;
    using SafeCast for *;
    using ProtocolFeeLibrary for uint24;
    using StateLibrary for IPoolManager;

    event UnlockCallback();
    event ProtocolFeeControllerUpdated(address feeController);
    event ModifyLiquidity(
        PoolId indexed poolId,
        address indexed sender,
        int24 tickLower,
        int24 tickUpper,
        int256 liquidityDelta,
        bytes32 salt
    );
    event Swap(
        PoolId indexed poolId,
        address indexed sender,
        int128 amount0,
        int128 amount1,
        uint160 sqrtPriceX96,
        uint128 liquidity,
        int24 tick,
        uint24 fee
    );

    event Donate(PoolId indexed id, address indexed sender, uint256 amount0, uint256 amount1);

    event Transfer(
        address caller, address indexed sender, address indexed receiver, uint256 indexed id, uint256 amount
    );

    uint24 constant MAX_PROTOCOL_FEE_BOTH_TOKENS = (1000 << 12) | 1000; // 1000 1000

    address hookAddr;
    Hooks.Permissions flag;
    uint24 FEE;
    function setUp() public {
        address forFlag = address(uint160(Hooks.ALL_HOOK_MASK));

        string memory code_json = vm.readFile("test/_inputBytecode/_kenny_GasPriceFeesHook.json");
        // string memory code_json = vm.readFile("test/_inputBytecode/_kenny_PointsHook.json");
        // string memory code_json = vm.readFile("test/_inputBytecode/_kenny_TakeProfitsHook.json");
        // string memory code_json = vm.readFile("test/_inputBytecode/_sori_backdoor.json");
        // string memory code_json = vm.readFile("test/_inputBytecode/_sori_slot0-oracle.json");
        // string memory code_json = vm.readFile("test/_inputBytecode/_sori_time.json");
        
        bytes memory bytecode = vm.parseJsonBytes(code_json, ".bytecode.object");
        bytes memory deployBytecode = vm.parseJsonBytes(code_json, ".deployedBytecode.object"); // runtimecode
        vm.etch(forFlag, deployBytecode);

        (bool success, bytes memory returnData) = forFlag.call(abi.encodeWithSignature("getHookPermissions()"));
        flag = abi.decode(returnData, (Hooks.Permissions));
        hookAddr = generateHookAddress();
        // (bool success, bytes memory returnData) = addr.call(abi.encodeWithSignature("isDynamicFee()"));
        // bool isDynamic = abi.decode(returnData, (bool));
        // FEE = isDynamic ? LPFeeLibrary.DYNAMIC_FEE_FLAG : Constants.FEE_MEDIUM;

        FEE = LPFeeLibrary.DYNAMIC_FEE_FLAG;
        // FEE = Constants.FEE_MEDIUM;

        deployFreshManagerAndRouters();
        deployMintAndApprove2Currencies();

        bytes memory withconstructor = abi.encodePacked(bytecode, abi.encode(manager, "test"));
        vm.etch(hookAddr, withconstructor);
        (success, returnData) = hookAddr.call("");
        vm.etch(hookAddr, returnData);

        custom_initializeManagerRoutersAndPoolsWithLiq(IHooks(hookAddr));
    }

    function test_addLiquidity_failsIfNotInitialized() public {
        vm.expectRevert(Pool.PoolNotInitialized.selector);
        modifyLiquidityRouter.modifyLiquidity(uninitializedKey, LIQUIDITY_PARAMS, ZERO_BYTES);
    }

    function test_addLiquidity_failsIfLocked() public {
        vm.expectRevert(IPoolManager.ManagerLocked.selector);
        manager.modifyLiquidity(uninitializedKey, LIQUIDITY_PARAMS, ZERO_BYTES);
    }

    function test_removeLiquidity_failsIfNotInitialized() public {
        vm.expectRevert(Pool.PoolNotInitialized.selector);
        modifyLiquidityRouter.modifyLiquidity(uninitializedKey, REMOVE_LIQUIDITY_PARAMS, ZERO_BYTES);
    }

    function test_removeLiquidity_failsIfLocked() public {
        vm.expectRevert(IPoolManager.ManagerLocked.selector);
        manager.modifyLiquidity(key, REMOVE_LIQUIDITY_PARAMS, ZERO_BYTES);
    }

    function test_addLiquidity_succeedsIfInitialized(uint160 sqrtPriceX96) public {
        sqrtPriceX96 = uint160(bound(sqrtPriceX96, TickMath.MIN_SQRT_PRICE, TickMath.MAX_SQRT_PRICE - 1));

        vm.expectEmit(true, true, false, true, address(manager));
        emit ModifyLiquidity(
            key.toId(),
            address(modifyLiquidityRouter),
            LIQUIDITY_PARAMS.tickLower,
            LIQUIDITY_PARAMS.tickUpper,
            LIQUIDITY_PARAMS.liquidityDelta,
            LIQUIDITY_PARAMS.salt
        );

        modifyLiquidityRouter.modifyLiquidity(key, LIQUIDITY_PARAMS, ZERO_BYTES);
    }

    function test_removeLiquidity_succeedsIfInitialized(uint160 sqrtPriceX96) public {
        sqrtPriceX96 = uint160(bound(sqrtPriceX96, TickMath.MIN_SQRT_PRICE, TickMath.MAX_SQRT_PRICE - 1));

        vm.expectEmit(true, true, false, true, address(manager));
        emit ModifyLiquidity(
            key.toId(),
            address(modifyLiquidityRouter),
            REMOVE_LIQUIDITY_PARAMS.tickLower,
            REMOVE_LIQUIDITY_PARAMS.tickUpper,
            REMOVE_LIQUIDITY_PARAMS.liquidityDelta,
            LIQUIDITY_PARAMS.salt
        );

        modifyLiquidityRouter.modifyLiquidity(key, REMOVE_LIQUIDITY_PARAMS, ZERO_BYTES);
    }

    function test_addLiquidity_succeedsForNativeTokensIfInitialized(uint160 sqrtPriceX96) public {
        sqrtPriceX96 = uint160(bound(sqrtPriceX96, TickMath.MIN_SQRT_PRICE, TickMath.MAX_SQRT_PRICE - 1));

        vm.expectEmit(true, true, false, true, address(manager));
        emit ModifyLiquidity(
            nativeKey.toId(),
            address(modifyLiquidityRouter),
            LIQUIDITY_PARAMS.tickLower,
            LIQUIDITY_PARAMS.tickUpper,
            LIQUIDITY_PARAMS.liquidityDelta,
            LIQUIDITY_PARAMS.salt
        );

        modifyLiquidityRouter.modifyLiquidity{value: 1 ether}(nativeKey, LIQUIDITY_PARAMS, ZERO_BYTES);
    }

    function test_removeLiquidity_succeedsForNativeTokensIfInitialized(uint160 sqrtPriceX96) public {
        sqrtPriceX96 = uint160(bound(sqrtPriceX96, TickMath.MIN_SQRT_PRICE, TickMath.MAX_SQRT_PRICE - 1));

        vm.expectEmit(true, true, false, true, address(manager));
        emit ModifyLiquidity(
            nativeKey.toId(),
            address(modifyLiquidityRouter),
            REMOVE_LIQUIDITY_PARAMS.tickLower,
            REMOVE_LIQUIDITY_PARAMS.tickUpper,
            REMOVE_LIQUIDITY_PARAMS.liquidityDelta,
            LIQUIDITY_PARAMS.salt
        );

        modifyLiquidityRouter.modifyLiquidity{value: 1 ether}(nativeKey, REMOVE_LIQUIDITY_PARAMS, ZERO_BYTES);
    }

    function test_addLiquidity_succeedsWithHooksIfInitialized(uint160 sqrtPriceX96) public {
        if (!flag.beforeAddLiquidity && !flag.afterAddLiquidity) {
            emit log_string("Skip Test");
            return;
        }
        sqrtPriceX96 = uint160(bound(sqrtPriceX96, TickMath.MIN_SQRT_PRICE, TickMath.MAX_SQRT_PRICE - 1));

        address payable mockAddr = payable(address(uint160(address(hookAddr)) ^ (0xffffffff << 128)));

        MockContract mockContract = new MockContract();
        vm.etch(mockAddr, address(mockContract).code);

        MockContract(mockAddr).setImplementation(hookAddr);

        (key,) = initPool(currency0, currency1, IHooks(mockAddr), 3000, sqrtPriceX96, ZERO_BYTES);

        BalanceDelta balanceDelta = modifyLiquidityRouter.modifyLiquidity(key, LIQUIDITY_PARAMS, ZERO_BYTES);

        if (flag.beforeAddLiquidity) {
            bytes32 beforeSelector = MockHooks.beforeAddLiquidity.selector;
            bytes memory beforeParams = abi.encode(address(modifyLiquidityRouter), key, LIQUIDITY_PARAMS, ZERO_BYTES);
            assertEq(MockContract(mockAddr).timesCalledSelector(beforeSelector), 1);
            assertTrue(MockContract(mockAddr).calledWithSelector(beforeSelector, beforeParams));
        }
        if (flag.afterAddLiquidity) {
            bytes32 afterSelector = MockHooks.afterAddLiquidity.selector;
            bytes memory afterParams = abi.encode(
                address(modifyLiquidityRouter),
                key,
                LIQUIDITY_PARAMS,
                balanceDelta,
                BalanceDeltaLibrary.ZERO_DELTA,
                ZERO_BYTES
            );
            assertEq(MockContract(mockAddr).timesCalledSelector(afterSelector), 1);
            assertTrue(MockContract(mockAddr).calledWithSelector(afterSelector, afterParams));
        }
    }

    function test_removeLiquidity_succeedsWithHooksIfInitialized(uint160 sqrtPriceX96) public {
        if (!flag.beforeRemoveLiquidity && !flag.afterRemoveLiquidity) {
            emit log_string("Skip Test");
            return;
        }
        sqrtPriceX96 = uint160(bound(sqrtPriceX96, TickMath.MIN_SQRT_PRICE, TickMath.MAX_SQRT_PRICE - 1));

        address payable mockAddr = payable(address(uint160(address(hookAddr)) ^ (0xffffffff << 128)));

        MockContract mockContract = new MockContract();
        vm.etch(mockAddr, address(mockContract).code);

        MockContract(mockAddr).setImplementation(hookAddr);

        (key,) = initPool(currency0, currency1, IHooks(mockAddr), 3000, sqrtPriceX96, ZERO_BYTES);

        modifyLiquidityRouter.modifyLiquidity(key, LIQUIDITY_PARAMS, ZERO_BYTES);
        BalanceDelta balanceDelta = modifyLiquidityRouter.modifyLiquidity(key, REMOVE_LIQUIDITY_PARAMS, ZERO_BYTES);

        if (flag.beforeRemoveLiquidity) {
            bytes32 beforeSelector = MockHooks.beforeRemoveLiquidity.selector;
            bytes memory beforeParams = abi.encode(address(modifyLiquidityRouter), key, REMOVE_LIQUIDITY_PARAMS, ZERO_BYTES);
            assertEq(MockContract(mockAddr).timesCalledSelector(beforeSelector), 1);
            assertTrue(MockContract(mockAddr).calledWithSelector(beforeSelector, beforeParams));
        }
        if (flag.afterRemoveLiquidity) {
            bytes32 afterSelector = MockHooks.afterRemoveLiquidity.selector;
            bytes memory afterParams = abi.encode(
                address(modifyLiquidityRouter),
                key,
                REMOVE_LIQUIDITY_PARAMS,
                balanceDelta,
                BalanceDeltaLibrary.ZERO_DELTA,
                ZERO_BYTES
            );
            assertEq(MockContract(mockAddr).timesCalledSelector(afterSelector), 1);
            assertTrue(MockContract(mockAddr).calledWithSelector(afterSelector, afterParams));
        }
    }

    function test_addLiquidity_failsWithIncorrectSelectors() public {
        if (!flag.beforeAddLiquidity && !flag.afterAddLiquidity) {
            emit log_string("Skip Test");
            return;
        }
        address payable mockAddr = payable(address(uint160(address(hookAddr)) ^ (0xffffffff << 128)));
        MockHooks impl = new MockHooks();
        vm.etch(mockAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(mockAddr);

        (key,) = initPool(currency0, currency1, mockHooks, 100, SQRT_PRICE_1_1, ZERO_BYTES);

        mockHooks.setReturnValue(mockHooks.beforeAddLiquidity.selector, bytes4(0xdeadbeef));
        mockHooks.setReturnValue(mockHooks.afterAddLiquidity.selector, bytes4(0xdeadbeef));

        if (flag.beforeAddLiquidity) {
            // Fails at beforeAddLiquidity hook.
            vm.expectRevert(Hooks.InvalidHookResponse.selector);
            modifyLiquidityRouter.modifyLiquidity(key, LIQUIDITY_PARAMS, ZERO_BYTES);
        }
        if (flag.afterAddLiquidity) {
            // Fail at afterAddLiquidity hook.
            mockHooks.setReturnValue(mockHooks.beforeAddLiquidity.selector, mockHooks.beforeAddLiquidity.selector);
            vm.expectRevert(Hooks.InvalidHookResponse.selector);
            modifyLiquidityRouter.modifyLiquidity(key, LIQUIDITY_PARAMS, ZERO_BYTES);
        }
    }

    function test_removeLiquidity_failsWithIncorrectSelectors() public {
        if (!flag.beforeRemoveLiquidity && !flag.afterRemoveLiquidity) {
            emit log_string("Skip Test");
            return;
        }
        address payable mockAddr = payable(address(uint160(address(hookAddr)) ^ (0xffffffff << 128)));
        MockHooks impl = new MockHooks();
        vm.etch(mockAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(mockAddr);

        (key,) = initPool(currency0, currency1, mockHooks, 100, SQRT_PRICE_1_1, ZERO_BYTES);
        modifyLiquidityRouter.modifyLiquidity(key, LIQUIDITY_PARAMS, ZERO_BYTES);

        mockHooks.setReturnValue(mockHooks.beforeRemoveLiquidity.selector, bytes4(0xdeadbeef));
        mockHooks.setReturnValue(mockHooks.afterRemoveLiquidity.selector, bytes4(0xdeadbeef));

        if (flag.beforeRemoveLiquidity) {
            // Fails at beforeRemoveLiquidity hook.
            vm.expectRevert(Hooks.InvalidHookResponse.selector);
            modifyLiquidityRouter.modifyLiquidity(key, REMOVE_LIQUIDITY_PARAMS, ZERO_BYTES);
        }
        if (flag.afterRemoveLiquidity) {
            // Fail at afterRemoveLiquidity hook.
            mockHooks.setReturnValue(mockHooks.beforeRemoveLiquidity.selector, mockHooks.beforeRemoveLiquidity.selector);
            vm.expectRevert(Hooks.InvalidHookResponse.selector);
            modifyLiquidityRouter.modifyLiquidity(key, REMOVE_LIQUIDITY_PARAMS, ZERO_BYTES);
        }
    }

    function test_addLiquidity_succeedsWithCorrectSelectors() public {
        if (!flag.beforeAddLiquidity && !flag.afterAddLiquidity) {
            emit log_string("Skip Test");
            return;
        }
        address payable mockAddr = payable(address(uint160(address(hookAddr)) ^ (0xffffffff << 128)));
        MockHooks impl = new MockHooks();
        vm.etch(mockAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(mockAddr);

        (key,) = initPool(currency0, currency1, mockHooks, 100, SQRT_PRICE_1_1, ZERO_BYTES);

        mockHooks.setReturnValue(mockHooks.beforeAddLiquidity.selector, mockHooks.beforeAddLiquidity.selector);
        mockHooks.setReturnValue(mockHooks.afterAddLiquidity.selector, mockHooks.afterAddLiquidity.selector);

        vm.expectEmit(true, true, false, true, address(manager));
        emit ModifyLiquidity(
            key.toId(),
            address(modifyLiquidityRouter),
            LIQUIDITY_PARAMS.tickLower,
            LIQUIDITY_PARAMS.tickUpper,
            LIQUIDITY_PARAMS.liquidityDelta,
            LIQUIDITY_PARAMS.salt
        );

        modifyLiquidityRouter.modifyLiquidity(key, LIQUIDITY_PARAMS, ZERO_BYTES);
    }

    function test_removeLiquidity_succeedsWithCorrectSelectors() public {
        if (!flag.beforeRemoveLiquidity && !flag.afterRemoveLiquidity) {
            emit log_string("Skip Test");
            return;
        }
        address payable mockAddr = payable(address(uint160(address(hookAddr)) ^ (0xffffffff << 128)));
        MockHooks impl = new MockHooks();
        vm.etch(mockAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(mockAddr);

        (key,) = initPool(currency0, currency1, mockHooks, 100, SQRT_PRICE_1_1, ZERO_BYTES);
        modifyLiquidityRouter.modifyLiquidity(key, LIQUIDITY_PARAMS, ZERO_BYTES);

        mockHooks.setReturnValue(mockHooks.beforeRemoveLiquidity.selector, mockHooks.beforeRemoveLiquidity.selector);
        mockHooks.setReturnValue(mockHooks.afterRemoveLiquidity.selector, mockHooks.afterRemoveLiquidity.selector);

        vm.expectEmit(true, true, false, true, address(manager));
        emit ModifyLiquidity(
            key.toId(),
            address(modifyLiquidityRouter),
            REMOVE_LIQUIDITY_PARAMS.tickLower,
            REMOVE_LIQUIDITY_PARAMS.tickUpper,
            REMOVE_LIQUIDITY_PARAMS.liquidityDelta,
            REMOVE_LIQUIDITY_PARAMS.salt
        );

        modifyLiquidityRouter.modifyLiquidity(key, REMOVE_LIQUIDITY_PARAMS, ZERO_BYTES);
    }

    function test_addLiquidity_6909() public {
        // convert test tokens into ERC6909 claims
        claimsRouter.deposit(currency0, address(this), 10_000e18);
        claimsRouter.deposit(currency1, address(this), 10_000e18);
        assertEq(manager.balanceOf(address(this), currency0.toId()), 10_000e18);
        assertEq(manager.balanceOf(address(this), currency1.toId()), 10_000e18);

        uint256 currency0BalanceBefore = currency0.balanceOfSelf();
        uint256 currency1BalanceBefore = currency1.balanceOfSelf();
        uint256 currency0PMBalanceBefore = currency0.balanceOf(address(manager));
        uint256 currency1PMBalanceBefore = currency1.balanceOf(address(manager));

        // allow liquidity router to burn our 6909 tokens
        manager.setOperator(address(modifyLiquidityRouter), true);

        // add liquidity with 6909: settleUsingBurn=true, takeClaims=true (unused)
        modifyLiquidityRouter.modifyLiquidity(key, LIQUIDITY_PARAMS, ZERO_BYTES, true, true);

        assertLt(manager.balanceOf(address(this), currency0.toId()), 10_000e18);
        assertLt(manager.balanceOf(address(this), currency1.toId()), 10_000e18);

        // ERC20s are unspent
        assertEq(currency0.balanceOfSelf(), currency0BalanceBefore);
        assertEq(currency1.balanceOfSelf(), currency1BalanceBefore);

        // PoolManager did not receive net-new ERC20s
        assertEq(currency0.balanceOf(address(manager)), currency0PMBalanceBefore);
        assertEq(currency1.balanceOf(address(manager)), currency1PMBalanceBefore);
    }

    function test_removeLiquidity_6909() public {
        modifyLiquidityRouter.modifyLiquidity(key, LIQUIDITY_PARAMS, ZERO_BYTES);

        assertEq(manager.balanceOf(address(this), currency0.toId()), 0);
        assertEq(manager.balanceOf(address(this), currency1.toId()), 0);

        uint256 currency0BalanceBefore = currency0.balanceOfSelf();
        uint256 currency1BalanceBefore = currency1.balanceOfSelf();
        uint256 currency0PMBalanceBefore = currency0.balanceOf(address(manager));
        uint256 currency1PMBalanceBefore = currency1.balanceOf(address(manager));

        // remove liquidity as 6909: settleUsingBurn=true (unused), takeClaims=true
        modifyLiquidityRouter.modifyLiquidity(key, REMOVE_LIQUIDITY_PARAMS, ZERO_BYTES, true, true);

        assertTrue(manager.balanceOf(address(this), currency0.toId()) > 0);
        assertTrue(manager.balanceOf(address(this), currency1.toId()) > 0);

        // ERC20s are unspent
        assertEq(currency0.balanceOfSelf(), currency0BalanceBefore);
        assertEq(currency1.balanceOfSelf(), currency1BalanceBefore);

        // PoolManager did lose ERC-20s
        assertEq(currency0.balanceOf(address(manager)), currency0PMBalanceBefore);
        assertEq(currency1.balanceOf(address(manager)), currency1PMBalanceBefore);
    }

    function test_addLiquidity_gas() public {
        IPoolManager.ModifyLiquidityParams memory uniqueParams =
            IPoolManager.ModifyLiquidityParams({tickLower: -300, tickUpper: -180, liquidityDelta: 1e18, salt: 0});
        modifyLiquidityNoChecks.modifyLiquidity(key, uniqueParams, ZERO_BYTES);
        snapLastCall("simple addLiquidity");
    }

    function test_addLiquidity_secondAdditionSameRange_gas() public {
        IPoolManager.ModifyLiquidityParams memory uniqueParams =
            IPoolManager.ModifyLiquidityParams({tickLower: -300, tickUpper: -180, liquidityDelta: 1e18, salt: 0});
        modifyLiquidityNoChecks.modifyLiquidity(key, uniqueParams, ZERO_BYTES);
        modifyLiquidityNoChecks.modifyLiquidity(key, uniqueParams, ZERO_BYTES);
        snapLastCall("simple addLiquidity second addition same range");
    }

    function test_removeLiquidity_gas() public {
        IPoolManager.ModifyLiquidityParams memory uniqueParams =
            IPoolManager.ModifyLiquidityParams({tickLower: -300, tickUpper: -180, liquidityDelta: 1e18, salt: 0});
        // add some liquidity to remove
        modifyLiquidityNoChecks.modifyLiquidity(key, uniqueParams, ZERO_BYTES);

        uniqueParams.liquidityDelta *= -1;
        modifyLiquidityNoChecks.modifyLiquidity(key, uniqueParams, ZERO_BYTES);
        snapLastCall("simple removeLiquidity");
    }

    function test_removeLiquidity_someLiquidityRemains_gas() public {
        // add double the liquidity to remove
        IPoolManager.ModifyLiquidityParams memory uniqueParams =
            IPoolManager.ModifyLiquidityParams({tickLower: -300, tickUpper: -180, liquidityDelta: 1e18, salt: 0});
        modifyLiquidityNoChecks.modifyLiquidity(key, uniqueParams, ZERO_BYTES);

        uniqueParams.liquidityDelta /= -2;
        modifyLiquidityNoChecks.modifyLiquidity(key, uniqueParams, ZERO_BYTES);
        snapLastCall("simple removeLiquidity some liquidity remains");
    }

    function test_addLiquidity_succeeds() public {
        modifyLiquidityRouter.modifyLiquidity(key, LIQUIDITY_PARAMS, ZERO_BYTES);
    }

    function test_removeLiquidity_succeeds() public {
        modifyLiquidityRouter.modifyLiquidity(key, REMOVE_LIQUIDITY_PARAMS, ZERO_BYTES);
    }

    function test_addLiquidity_withNative_gas() public {
        modifyLiquidityRouter.modifyLiquidity{value: 1 ether}(nativeKey, LIQUIDITY_PARAMS, ZERO_BYTES);
        snapLastCall("addLiquidity with native token");
    }

    function test_removeLiquidity_withNative_gas() public {
        modifyLiquidityRouter.modifyLiquidity{value: 1 ether}(nativeKey, REMOVE_LIQUIDITY_PARAMS, ZERO_BYTES);
        snapLastCall("removeLiquidity with native token");
    }

    function test_addLiquidity_withHooks_gas() public {
        address allHooksAddr = Constants.ALL_HOOKS;
        MockHooks impl = new MockHooks();
        vm.etch(allHooksAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(allHooksAddr);

        (key,) = initPool(currency0, currency1, mockHooks, 3000, SQRT_PRICE_1_1, ZERO_BYTES);

        modifyLiquidityRouter.modifyLiquidity(key, LIQUIDITY_PARAMS, ZERO_BYTES);
        snapLastCall("addLiquidity with empty hook");
    }

    function test_removeLiquidity_withHooks_gas() public {
        address allHooksAddr = Constants.ALL_HOOKS;
        MockHooks impl = new MockHooks();
        vm.etch(allHooksAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(allHooksAddr);

        (key,) = initPool(currency0, currency1, mockHooks, 3000, SQRT_PRICE_1_1, ZERO_BYTES);
        modifyLiquidityRouter.modifyLiquidity(key, LIQUIDITY_PARAMS, ZERO_BYTES);

        modifyLiquidityRouter.modifyLiquidity(key, REMOVE_LIQUIDITY_PARAMS, ZERO_BYTES);
        snapLastCall("removeLiquidity with empty hook");
    }

    function test_swap_failsIfNotInitialized(uint160 sqrtPriceX96) public {
        sqrtPriceX96 = uint160(bound(sqrtPriceX96, TickMath.MIN_SQRT_PRICE, TickMath.MAX_SQRT_PRICE - 1));

        key.fee = 100;
        IPoolManager.SwapParams memory params =
            IPoolManager.SwapParams({zeroForOne: true, amountSpecified: -100, sqrtPriceLimitX96: sqrtPriceX96});

        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});

        vm.expectRevert(Pool.PoolNotInitialized.selector);
        swapRouter.swap(key, params, testSettings, ZERO_BYTES);
    }

    function test_swap_succeedsIfInitialized() public {
        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: true, settleUsingBurn: false});

        swapRouter.swap(key, SWAP_PARAMS, testSettings, ZERO_BYTES);
    }

    function test_swap_failsIfLocked() public {
        vm.expectRevert(IPoolManager.ManagerLocked.selector);
        manager.swap(key, SWAP_PARAMS, ZERO_BYTES);
    }

    function test_swap_succeedsWithNativeTokensIfInitialized() public {
        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: true, settleUsingBurn: false});

        swapRouter.swap{value: 100}(nativeKey, SWAP_PARAMS, testSettings, ZERO_BYTES);
    }

    function test_swap_succeedsWithHooksIfInitialized() public {
        if (!flag.beforeSwap && !flag.afterSwap) {
            emit log_string("Skip Test");
            return;
        }
        address payable mockAddr = payable(address(uint160(address(hookAddr)) ^ (0xffffffff << 128)));

        MockContract mockContract = new MockContract();
        vm.etch(mockAddr, address(mockContract).code);

        MockContract(mockAddr).setImplementation(hookAddr);

        (key,) = initPoolAndAddLiquidity(currency0, currency1, IHooks(mockAddr), FEE, SQRT_PRICE_1_1, ZERO_BYTES);

        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: true, settleUsingBurn: false});

        BalanceDelta balanceDelta = swapRouter.swap(key, SWAP_PARAMS, testSettings, ZERO_BYTES);

        if (flag.beforeSwap) {
            bytes32 beforeSelector = MockHooks.beforeSwap.selector;
            bytes memory beforeParams = abi.encode(address(swapRouter), key, SWAP_PARAMS, ZERO_BYTES);
            assertEq(MockContract(mockAddr).timesCalledSelector(beforeSelector), 1);
            assertTrue(MockContract(mockAddr).calledWithSelector(beforeSelector, beforeParams));
        }
        if (flag.afterSwap) {
            bytes32 afterSelector = MockHooks.afterSwap.selector;
            bytes memory afterParams = abi.encode(address(swapRouter), key, SWAP_PARAMS, balanceDelta, ZERO_BYTES);
            assertEq(MockContract(mockAddr).timesCalledSelector(afterSelector), 1);
            assertTrue(MockContract(mockAddr).calledWithSelector(afterSelector, afterParams));
        }
    }

    function test_swap_failsWithIncorrectSelectors() public {
        if (!flag.beforeSwap && !flag.afterSwap) {
            emit log_string("Skip Test");
            return;
        }
        address payable mockAddr = payable(address(uint160(address(hookAddr)) ^ (0xffffffff << 128)));
        MockHooks impl = new MockHooks();
        vm.etch(mockAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(mockAddr);

        (key,) = initPoolAndAddLiquidity(currency0, currency1, mockHooks, 100, SQRT_PRICE_1_1, ZERO_BYTES);

        IPoolManager.SwapParams memory swapParams =
            IPoolManager.SwapParams({zeroForOne: true, amountSpecified: 10, sqrtPriceLimitX96: SQRT_PRICE_1_2});

        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: true, settleUsingBurn: false});

        mockHooks.setReturnValue(mockHooks.beforeSwap.selector, bytes4(0xdeadbeef));
        mockHooks.setReturnValue(mockHooks.afterSwap.selector, bytes4(0xdeadbeef));

        if (flag.beforeSwap) {
            // Fails at beforeSwap hook.
            vm.expectRevert(Hooks.InvalidHookResponse.selector);
            swapRouter.swap(key, swapParams, testSettings, ZERO_BYTES);
        }
        if (flag.afterSwap) {
            // Fail at afterSwap hook.
            mockHooks.setReturnValue(mockHooks.beforeSwap.selector, mockHooks.beforeSwap.selector);
            vm.expectRevert(Hooks.InvalidHookResponse.selector);
            swapRouter.swap(key, swapParams, testSettings, ZERO_BYTES);
        }
    }

    function test_swap_succeedsWithCorrectSelectors() public {
        if (!flag.beforeSwap && !flag.afterSwap) {
            emit log_string("Skip Test");
            return;
        }
        address payable mockAddr = payable(address(uint160(address(hookAddr)) ^ (0xffffffff << 128)));
        MockHooks impl = new MockHooks();
        vm.etch(mockAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(mockAddr);

        (key,) = initPoolAndAddLiquidity(currency0, currency1, mockHooks, 100, SQRT_PRICE_1_1, ZERO_BYTES);

        IPoolManager.SwapParams memory swapParams =
            IPoolManager.SwapParams({zeroForOne: true, amountSpecified: -10, sqrtPriceLimitX96: SQRT_PRICE_1_2});

        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: true, settleUsingBurn: false});

        mockHooks.setReturnValue(mockHooks.beforeSwap.selector, mockHooks.beforeSwap.selector);
        mockHooks.setReturnValue(mockHooks.afterSwap.selector, mockHooks.afterSwap.selector);

        swapRouter.swap(key, swapParams, testSettings, ZERO_BYTES);
    }

    function test_swap_succeeds() public {
        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});

        swapRouter.swap(key, SWAP_PARAMS, testSettings, ZERO_BYTES);
    }

    function test_swap_gas() public {
        swapRouterNoChecks.swap(key, SWAP_PARAMS);
        snapLastCall("simple swap");
    }

    function test_swap_withNative_succeeds() public {
        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});

        swapRouter.swap{value: 100}(nativeKey, SWAP_PARAMS, testSettings, ZERO_BYTES);
    }

    function test_swap_withNative_gas() public {
        swapRouterNoChecks.swap{value: 100}(nativeKey, SWAP_PARAMS);
        snapLastCall("simple swap with native");
    }

    function test_swap_withHooks_gas() public {
        address allHooksAddr = Constants.ALL_HOOKS;

        MockHooks impl = new MockHooks();
        vm.etch(allHooksAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(allHooksAddr);

        (key,) = initPoolAndAddLiquidity(currency0, currency1, mockHooks, 3000, SQRT_PRICE_1_1, ZERO_BYTES);

        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});

        swapRouter.swap(key, SWAP_PARAMS, testSettings, ZERO_BYTES);

        IPoolManager.SwapParams memory swapParams =
            IPoolManager.SwapParams({zeroForOne: true, amountSpecified: -100, sqrtPriceLimitX96: SQRT_PRICE_1_4});
        testSettings = PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});

        swapRouter.swap(key, swapParams, testSettings, ZERO_BYTES);
        snapLastCall("swap with hooks");
    }

    function test_swap_mint6909IfOutputNotTaken_gas() public {
        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: true, settleUsingBurn: false});

        vm.expectEmit();
        emit Transfer(address(swapRouter), address(0), address(this), CurrencyLibrary.toId(currency1), 98);
        swapRouter.swap(key, SWAP_PARAMS, testSettings, ZERO_BYTES);
        snapLastCall("swap mint output as 6909");

        uint256 erc6909Balance = manager.balanceOf(address(this), CurrencyLibrary.toId(currency1));
        assertEq(erc6909Balance, 98);
    }

    function test_swap_mint6909IfNativeOutputNotTaken_gas() public {
        IPoolManager.SwapParams memory params =
            IPoolManager.SwapParams({zeroForOne: false, amountSpecified: -100, sqrtPriceLimitX96: SQRT_PRICE_2_1});

        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: true, settleUsingBurn: false});

        vm.expectEmit();
        emit Transfer(
            address(swapRouter), address(0), address(this), CurrencyLibrary.toId(CurrencyLibrary.ADDRESS_ZERO), 98
        );
        swapRouter.swap(nativeKey, params, testSettings, ZERO_BYTES);
        snapLastCall("swap mint native output as 6909");

        uint256 erc6909Balance = manager.balanceOf(address(this), CurrencyLibrary.toId(CurrencyLibrary.ADDRESS_ZERO));
        assertEq(erc6909Balance, 98);
    }

    function test_swap_burn6909AsInput_gas() public {
        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: true, settleUsingBurn: false});

        vm.expectEmit();
        emit Transfer(address(swapRouter), address(0), address(this), CurrencyLibrary.toId(currency1), 98);
        swapRouter.swap(key, SWAP_PARAMS, testSettings, ZERO_BYTES);

        uint256 erc6909Balance = manager.balanceOf(address(this), uint256(uint160(Currency.unwrap(currency1))));
        assertEq(erc6909Balance, 98);

        // give permission for swapRouter to burn the 6909s
        manager.setOperator(address(swapRouter), true);

        // swap from currency1 to currency0 again, using 6909s as input tokens
        IPoolManager.SwapParams memory params =
            IPoolManager.SwapParams({zeroForOne: false, amountSpecified: 25, sqrtPriceLimitX96: SQRT_PRICE_4_1});
        testSettings = PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: true});

        vm.expectEmit();
        emit Transfer(address(swapRouter), address(this), address(0), CurrencyLibrary.toId(currency1), 27);
        swapRouter.swap(key, params, testSettings, ZERO_BYTES);
        snapLastCall("swap burn 6909 for input");

        erc6909Balance = manager.balanceOf(address(this), CurrencyLibrary.toId(currency1));
        assertEq(erc6909Balance, 71);
    }

    function test_swap_burnNative6909AsInput_gas() public {
        IPoolManager.SwapParams memory params =
            IPoolManager.SwapParams({zeroForOne: false, amountSpecified: -100, sqrtPriceLimitX96: SQRT_PRICE_2_1});

        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: true, settleUsingBurn: false});

        vm.expectEmit();
        emit Transfer(
            address(swapRouter), address(0), address(this), CurrencyLibrary.toId(CurrencyLibrary.ADDRESS_ZERO), 98
        );
        swapRouter.swap(nativeKey, params, testSettings, ZERO_BYTES);

        uint256 erc6909Balance = manager.balanceOf(address(this), CurrencyLibrary.toId(CurrencyLibrary.ADDRESS_ZERO));
        assertEq(erc6909Balance, 98);

        // give permission for swapRouter to burn the 6909s
        manager.setOperator(address(swapRouter), true);

        // swap from currency0 to currency1, using 6909s as input tokens
        params = IPoolManager.SwapParams({zeroForOne: true, amountSpecified: 25, sqrtPriceLimitX96: SQRT_PRICE_1_4});
        testSettings = PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: true});

        vm.expectEmit();
        emit Transfer(
            address(swapRouter), address(this), address(0), CurrencyLibrary.toId(CurrencyLibrary.ADDRESS_ZERO), 27
        );
        // don't have to send in native currency since burning 6909 for input
        swapRouter.swap(nativeKey, params, testSettings, ZERO_BYTES);
        snapLastCall("swap burn native 6909 for input");

        erc6909Balance = manager.balanceOf(address(this), CurrencyLibrary.toId(CurrencyLibrary.ADDRESS_ZERO));
        assertEq(erc6909Balance, 71);
    }

    function test_swap_againstLiquidity_gas() public {
        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});

        swapRouter.swap(key, SWAP_PARAMS, testSettings, ZERO_BYTES);

        IPoolManager.SwapParams memory params =
            IPoolManager.SwapParams({zeroForOne: true, amountSpecified: -100, sqrtPriceLimitX96: SQRT_PRICE_1_4});

        swapRouter.swap(key, params, testSettings, ZERO_BYTES);
        snapLastCall("swap against liquidity");
    }

    function test_swap_againstLiqWithNative_gas() public {
        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});

        swapRouter.swap{value: 1 ether}(nativeKey, SWAP_PARAMS, testSettings, ZERO_BYTES);

        IPoolManager.SwapParams memory params =
            IPoolManager.SwapParams({zeroForOne: true, amountSpecified: -100, sqrtPriceLimitX96: SQRT_PRICE_1_4});

        swapRouter.swap{value: 1 ether}(nativeKey, params, testSettings, ZERO_BYTES);
        snapLastCall("swap against liquidity with native token");
    }

    function test_swap_accruesProtocolFees(uint16 protocolFee0, uint16 protocolFee1, int256 amountSpecified) public {
        protocolFee0 = uint16(bound(protocolFee0, 0, 1000));
        protocolFee1 = uint16(bound(protocolFee1, 0, 1000));
        vm.assume(amountSpecified != 0);

        uint24 protocolFee = (uint24(protocolFee1) << 12) | uint24(protocolFee0);

        (,, uint24 slot0ProtocolFee,) = manager.getSlot0(key.toId());
        assertEq(slot0ProtocolFee, 0);

        vm.prank(address(feeController));
        manager.setProtocolFee(key, protocolFee);

        (,, slot0ProtocolFee,) = manager.getSlot0(key.toId());
        assertEq(slot0ProtocolFee, protocolFee);

        // Add liquidity - Fees dont accrue for positive liquidity delta.
        IPoolManager.ModifyLiquidityParams memory params = LIQUIDITY_PARAMS;
        modifyLiquidityRouter.modifyLiquidity(key, params, ZERO_BYTES);

        assertEq(manager.protocolFeesAccrued(currency0), 0);
        assertEq(manager.protocolFeesAccrued(currency1), 0);

        // Remove liquidity - Fees dont accrue for negative liquidity delta.
        params.liquidityDelta = -LIQUIDITY_PARAMS.liquidityDelta;
        modifyLiquidityRouter.modifyLiquidity(key, params, ZERO_BYTES);

        assertEq(manager.protocolFeesAccrued(currency0), 0);
        assertEq(manager.protocolFeesAccrued(currency1), 0);

        // Now re-add the liquidity to test swap
        params.liquidityDelta = LIQUIDITY_PARAMS.liquidityDelta;
        modifyLiquidityRouter.modifyLiquidity(key, params, ZERO_BYTES);

        IPoolManager.SwapParams memory swapParams =
            IPoolManager.SwapParams(false, amountSpecified, TickMath.MAX_SQRT_PRICE - 1);
        BalanceDelta delta = swapRouter.swap(key, swapParams, PoolSwapTest.TestSettings(false, false), ZERO_BYTES);
        uint256 expectedProtocolFee =
            uint256(uint128(-delta.amount1())) * protocolFee1 / ProtocolFeeLibrary.PIPS_DENOMINATOR;
        assertEq(manager.protocolFeesAccrued(currency0), 0);
        assertEq(manager.protocolFeesAccrued(currency1), expectedProtocolFee);
    }

    function test_donate_failsIfNotInitialized() public {
        vm.expectRevert(Pool.PoolNotInitialized.selector);
        donateRouter.donate(uninitializedKey, 100, 100, ZERO_BYTES);
    }

    function test_donate_failsIfLocked() public {
        vm.expectRevert(IPoolManager.ManagerLocked.selector);
        manager.donate(key, 100, 100, ZERO_BYTES);
    }

    function test_donate_failsIfNoLiquidity(uint160 sqrtPriceX96) public {
        sqrtPriceX96 = uint160(bound(sqrtPriceX96, TickMath.MIN_SQRT_PRICE, TickMath.MAX_SQRT_PRICE - 1));

        (key,) = initPool(currency0, currency1, IHooks(address(0)), 100, sqrtPriceX96, ZERO_BYTES);

        vm.expectRevert(Pool.NoLiquidityToReceiveFees.selector);
        donateRouter.donate(key, 100, 100, ZERO_BYTES);
    }

    // test successful donation if pool has liquidity
    function test_donate_succeedsWhenPoolHasLiquidity() public {
        (uint256 feeGrowthGlobal0X128, uint256 feeGrowthGlobal1X128) = manager.getFeeGrowthGlobals(key.toId());
        assertEq(feeGrowthGlobal0X128, 0);
        assertEq(feeGrowthGlobal1X128, 0);

        donateRouter.donate(key, 100, 200, ZERO_BYTES);
        snapLastCall("donate gas with 2 tokens");

        (feeGrowthGlobal0X128, feeGrowthGlobal1X128) = manager.getFeeGrowthGlobals(key.toId());
        assertEq(feeGrowthGlobal0X128, 34028236692093846346337);
        assertEq(feeGrowthGlobal1X128, 68056473384187692692674);
    }

    function test_donate_succeedsForNativeTokensWhenPoolHasLiquidity() public {
        (uint256 feeGrowthGlobal0X128, uint256 feeGrowthGlobal1X128) = manager.getFeeGrowthGlobals(nativeKey.toId());
        assertEq(feeGrowthGlobal0X128, 0);
        assertEq(feeGrowthGlobal1X128, 0);

        donateRouter.donate{value: 100}(nativeKey, 100, 200, ZERO_BYTES);

        (feeGrowthGlobal0X128, feeGrowthGlobal1X128) = manager.getFeeGrowthGlobals(nativeKey.toId());
        assertEq(feeGrowthGlobal0X128, 34028236692093846346337);
        assertEq(feeGrowthGlobal1X128, 68056473384187692692674);
    }

    function test_donate_failsWithIncorrectSelectors() public {
        if (!flag.beforeDonate && !flag.afterDonate) {
            emit log_string("Skip Test");
            return;
        }
        address payable mockAddr = payable(address(uint160(address(hookAddr)) ^ (0xffffffff << 128)));
        MockHooks impl = new MockHooks();
        vm.etch(mockAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(mockAddr);
        (key,) = initPoolAndAddLiquidity(currency0, currency1, mockHooks, 100, SQRT_PRICE_1_1, ZERO_BYTES);

        mockHooks.setReturnValue(mockHooks.beforeDonate.selector, bytes4(0xdeadbeef));
        mockHooks.setReturnValue(mockHooks.afterDonate.selector, bytes4(0xdeadbeef));

        if (flag.beforeDonate) {
            // Fails at beforeDonate hook.
            vm.expectRevert(Hooks.InvalidHookResponse.selector);
            donateRouter.donate(key, 100, 200, ZERO_BYTES);
        }
        if (flag.afterDonate) {
            // Fail at afterDonate hook.
            mockHooks.setReturnValue(mockHooks.beforeDonate.selector, mockHooks.beforeDonate.selector);
            vm.expectRevert(Hooks.InvalidHookResponse.selector);
            donateRouter.donate(key, 100, 200, ZERO_BYTES);
        }
    }

    function test_donate_succeedsWithCorrectSelectors() public {
        if (!flag.beforeDonate && !flag.afterDonate) {
            emit log_string("Skip Test");
            return;
        }
        address payable mockAddr = payable(address(uint160(address(hookAddr)) ^ (0xffffffff << 128)));
        MockHooks impl = new MockHooks();
        vm.etch(mockAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(mockAddr);

        (key,) = initPoolAndAddLiquidity(currency0, currency1, mockHooks, 100, SQRT_PRICE_1_1, ZERO_BYTES);

        mockHooks.setReturnValue(mockHooks.beforeDonate.selector, mockHooks.beforeDonate.selector);
        mockHooks.setReturnValue(mockHooks.afterDonate.selector, mockHooks.afterDonate.selector);

        donateRouter.donate(key, 100, 200, ZERO_BYTES);
    }

    function test_donate_OneToken_gas() public {
        donateRouter.donate(key, 100, 0, ZERO_BYTES);
        snapLastCall("donate gas with 1 token");
    }

    function test_fuzz_donate_emits_event(uint256 amount0, uint256 amount1) public {
        amount0 = bound(amount0, 0, uint256(int256(type(int128).max)));
        amount1 = bound(amount1, 0, uint256(int256(type(int128).max)));

        vm.expectEmit(true, true, false, true, address(manager));
        emit Donate(key.toId(), address(donateRouter), uint256(amount0), uint256(amount1));
        donateRouter.donate(key, amount0, amount1, ZERO_BYTES);
    }

    function test_take_failsWithNoLiquidity() public {
        deployFreshManagerAndRouters();

        vm.expectRevert();
        takeRouter.take(key, 100, 0);
    }

    function test_take_failsWithInvalidTokensThatDoNotReturnTrueOnTransfer() public {
        TestInvalidERC20 invalidToken = new TestInvalidERC20(2 ** 255);
        Currency invalidCurrency = Currency.wrap(address(invalidToken));
        invalidToken.approve(address(modifyLiquidityRouter), type(uint256).max);
        invalidToken.approve(address(takeRouter), type(uint256).max);

        bool currency0Invalid = invalidCurrency < currency0;

        (key,) = initPoolAndAddLiquidity(
            (currency0Invalid ? invalidCurrency : currency0),
            (currency0Invalid ? currency0 : invalidCurrency),
            IHooks(address(0)),
            3000,
            SQRT_PRICE_1_1,
            ZERO_BYTES
        );

        (uint256 amount0, uint256 amount1) = currency0Invalid ? (1, 0) : (0, 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                CurrencyLibrary.Wrap__ERC20TransferFailed.selector, invalidToken, abi.encode(bytes32(0))
            )
        );
        takeRouter.take(key, amount0, amount1);

        // should not revert when non zero amount passed in for valid currency
        // assertions inside takeRouter because it takes then settles
        (amount0, amount1) = currency0Invalid ? (0, 1) : (1, 0);
        takeRouter.take(key, amount0, amount1);
    }

    function test_take_succeedsWithPoolWithLiquidity() public {
        takeRouter.take(key, 1, 1); // assertions inside takeRouter because it takes then settles
    }

    function test_take_failsIfLocked() public {
        vm.expectRevert(IPoolManager.ManagerLocked.selector);
        manager.take(key.currency0, address(this), 1);
    }

    function test_take_succeedsWithPoolWithLiquidityWithNativeToken() public {
        takeRouter.take{value: 1}(nativeKey, 1, 1); // assertions inside takeRouter because it takes then settles
    }

    function test_settle_failsIfLocked() public {
        vm.expectRevert(IPoolManager.ManagerLocked.selector);
        manager.settle();
    }

    function test_settle_revertsSendingNative_withTokenSynced() public {
        Actions[] memory actions = new Actions[](2);
        bytes[] memory params = new bytes[](2);

        actions[0] = Actions.SYNC;
        params[0] = abi.encode(key.currency0);

        // Revert with NonzeroNativeValue
        actions[1] = Actions.SETTLE_NATIVE;
        params[1] = abi.encode(1);

        vm.expectRevert(IPoolManager.NonzeroNativeValue.selector);
        actionsRouter.executeActions{value: 1}(actions, params);
    }

    function test_mint_failsIfLocked() public {
        vm.expectRevert(IPoolManager.ManagerLocked.selector);
        manager.mint(address(this), key.currency0.toId(), 1);
    }

    function test_burn_failsIfLocked() public {
        vm.expectRevert(IPoolManager.ManagerLocked.selector);
        manager.burn(address(this), key.currency0.toId(), 1);
    }

    function test_collectProtocolFees_ERC20_accumulateFees_gas() public {
        uint256 expectedFees = 10;

        (,, uint24 slot0ProtocolFee,) = manager.getSlot0(key.toId());
        assertEq(slot0ProtocolFee, 0);

        vm.prank(address(feeController));
        manager.setProtocolFee(key, MAX_PROTOCOL_FEE_BOTH_TOKENS);

        (,, slot0ProtocolFee,) = manager.getSlot0(key.toId());
        assertEq(slot0ProtocolFee, MAX_PROTOCOL_FEE_BOTH_TOKENS);

        swapRouter.swap(
            key,
            IPoolManager.SwapParams(true, -10000, SQRT_PRICE_1_2),
            PoolSwapTest.TestSettings(false, false),
            ZERO_BYTES
        );

        assertEq(manager.protocolFeesAccrued(currency0), expectedFees);
        assertEq(manager.protocolFeesAccrued(currency1), 0);
        assertEq(currency0.balanceOf(address(1)), 0);
        vm.prank(address(feeController));
        manager.collectProtocolFees(address(1), currency0, expectedFees);
        snapLastCall("erc20 collect protocol fees");
        assertEq(currency0.balanceOf(address(1)), expectedFees);
        assertEq(manager.protocolFeesAccrued(currency0), 0);
    }

    function test_collectProtocolFees_ERC20_accumulateFees_exactOutput() public {
        uint256 expectedFees = 10;

        (,, uint24 slot0ProtocolFee,) = manager.getSlot0(key.toId());
        assertEq(slot0ProtocolFee, 0);

        vm.prank(address(feeController));
        manager.setProtocolFee(key, MAX_PROTOCOL_FEE_BOTH_TOKENS);

        (,, slot0ProtocolFee,) = manager.getSlot0(key.toId());
        assertEq(slot0ProtocolFee, MAX_PROTOCOL_FEE_BOTH_TOKENS);

        swapRouter.swap(
            key,
            IPoolManager.SwapParams(true, 10000, SQRT_PRICE_1_2),
            PoolSwapTest.TestSettings(false, false),
            ZERO_BYTES
        );

        assertEq(manager.protocolFeesAccrued(currency0), expectedFees);
        assertEq(manager.protocolFeesAccrued(currency1), 0);
        assertEq(currency0.balanceOf(address(1)), 0);
        vm.prank(address(feeController));
        manager.collectProtocolFees(address(1), currency0, expectedFees);
        assertEq(currency0.balanceOf(address(1)), expectedFees);
        assertEq(manager.protocolFeesAccrued(currency0), 0);
    }

    function test_collectProtocolFees_ERC20_returnsAllFeesIf0IsProvidedAsParameter() public {
        uint256 expectedFees = 10;

        (,, uint24 slot0ProtocolFee,) = manager.getSlot0(key.toId());
        assertEq(slot0ProtocolFee, 0);

        vm.prank(address(feeController));
        manager.setProtocolFee(key, MAX_PROTOCOL_FEE_BOTH_TOKENS);

        (,, slot0ProtocolFee,) = manager.getSlot0(key.toId());
        assertEq(slot0ProtocolFee, MAX_PROTOCOL_FEE_BOTH_TOKENS);

        swapRouter.swap(
            key,
            IPoolManager.SwapParams(false, -10000, TickMath.MAX_SQRT_PRICE - 1),
            PoolSwapTest.TestSettings(false, false),
            ZERO_BYTES
        );

        assertEq(manager.protocolFeesAccrued(currency0), 0);
        assertEq(manager.protocolFeesAccrued(currency1), expectedFees);
        assertEq(currency1.balanceOf(address(1)), 0);
        vm.prank(address(feeController));
        manager.collectProtocolFees(address(1), currency1, 0);
        assertEq(currency1.balanceOf(address(1)), expectedFees);
        assertEq(manager.protocolFeesAccrued(currency1), 0);
    }

    function test_collectProtocolFees_nativeToken_accumulateFees_gas() public {
        uint256 expectedFees = 10;
        Currency nativeCurrency = CurrencyLibrary.ADDRESS_ZERO;

        (,, uint24 slot0ProtocolFee,) = manager.getSlot0(nativeKey.toId());
        assertEq(slot0ProtocolFee, 0);

        vm.prank(address(feeController));
        manager.setProtocolFee(nativeKey, MAX_PROTOCOL_FEE_BOTH_TOKENS);

        (,, slot0ProtocolFee,) = manager.getSlot0(nativeKey.toId());
        assertEq(slot0ProtocolFee, MAX_PROTOCOL_FEE_BOTH_TOKENS);

        swapRouter.swap{value: 10000}(
            nativeKey,
            IPoolManager.SwapParams(true, -10000, SQRT_PRICE_1_2),
            PoolSwapTest.TestSettings(false, false),
            ZERO_BYTES
        );

        assertEq(manager.protocolFeesAccrued(nativeCurrency), expectedFees);
        assertEq(manager.protocolFeesAccrued(currency1), 0);
        assertEq(nativeCurrency.balanceOf(address(1)), 0);
        vm.prank(address(feeController));
        manager.collectProtocolFees(address(1), nativeCurrency, expectedFees);
        snapLastCall("native collect protocol fees");
        assertEq(nativeCurrency.balanceOf(address(1)), expectedFees);
        assertEq(manager.protocolFeesAccrued(nativeCurrency), 0);
    }

    function test_collectProtocolFees_nativeToken_returnsAllFeesIf0IsProvidedAsParameter() public {
        uint256 expectedFees = 10;
        Currency nativeCurrency = CurrencyLibrary.ADDRESS_ZERO;

        (,, uint24 slot0ProtocolFee,) = manager.getSlot0(nativeKey.toId());
        assertEq(slot0ProtocolFee, 0);

        vm.prank(address(feeController));
        manager.setProtocolFee(nativeKey, MAX_PROTOCOL_FEE_BOTH_TOKENS);

        (,, slot0ProtocolFee,) = manager.getSlot0(nativeKey.toId());
        assertEq(slot0ProtocolFee, MAX_PROTOCOL_FEE_BOTH_TOKENS);

        swapRouter.swap{value: 10000}(
            nativeKey,
            IPoolManager.SwapParams(true, -10000, SQRT_PRICE_1_2),
            PoolSwapTest.TestSettings(false, false),
            ZERO_BYTES
        );

        assertEq(manager.protocolFeesAccrued(nativeCurrency), expectedFees);
        assertEq(manager.protocolFeesAccrued(currency1), 0);
        assertEq(nativeCurrency.balanceOf(address(1)), 0);
        vm.prank(address(feeController));
        manager.collectProtocolFees(address(1), nativeCurrency, 0);
        assertEq(nativeCurrency.balanceOf(address(1)), expectedFees);
        assertEq(manager.protocolFeesAccrued(nativeCurrency), 0);
    }

    Action[] _actions;

    function test_unlock_cannotBeCalledTwiceByCaller() public {
        _actions = [Action.NESTED_SELF_UNLOCK];
        nestedActionRouter.unlock(abi.encode(_actions));
    }

    function test_unlock_cannotBeCalledTwiceByDifferentCallers() public {
        _actions = [Action.NESTED_EXECUTOR_UNLOCK];
        nestedActionRouter.unlock(abi.encode(_actions));
    }

    function test_getPosition() public view {
        (uint128 liquidity,,) = manager.getPositionInfo(key.toId(), address(modifyLiquidityRouter), -120, 120, 0);
        assert(LIQUIDITY_PARAMS.liquidityDelta > 0);
        assertEq(liquidity, uint128(uint256(LIQUIDITY_PARAMS.liquidityDelta)));
    }

    function generateHookAddress() public view returns (address) {
        uint160 hookFlags = 0;

        if (flag.beforeInitialize) hookFlags |= Hooks.BEFORE_INITIALIZE_FLAG;
        if (flag.afterInitialize) hookFlags |= Hooks.AFTER_INITIALIZE_FLAG;
        if (flag.beforeAddLiquidity) hookFlags |= Hooks.BEFORE_ADD_LIQUIDITY_FLAG;
        if (flag.afterAddLiquidity) hookFlags |= Hooks.AFTER_ADD_LIQUIDITY_FLAG;
        if (flag.beforeRemoveLiquidity) hookFlags |= Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG;
        if (flag.afterRemoveLiquidity) hookFlags |= Hooks.AFTER_REMOVE_LIQUIDITY_FLAG;
        if (flag.beforeSwap) hookFlags |= Hooks.BEFORE_SWAP_FLAG;
        if (flag.afterSwap) hookFlags |= Hooks.AFTER_SWAP_FLAG;
        if (flag.beforeDonate) hookFlags |= Hooks.BEFORE_DONATE_FLAG;
        if (flag.afterDonate) hookFlags |= Hooks.AFTER_DONATE_FLAG;
        if (flag.beforeSwapReturnDelta) hookFlags |= Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG;
        if (flag.afterSwapReturnDelta) hookFlags |= Hooks.AFTER_SWAP_RETURNS_DELTA_FLAG;
        if (flag.afterAddLiquidityReturnDelta) hookFlags |= Hooks.AFTER_ADD_LIQUIDITY_RETURNS_DELTA_FLAG;
        if (flag.afterRemoveLiquidityReturnDelta) hookFlags |= Hooks.AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA_FLAG;

        return address(uint160(hookFlags));
    }

    // Deploys the manager, all test routers, and sets up 2 pools: with and without native
    function custom_initializeManagerRoutersAndPoolsWithLiq(IHooks hooks) internal {
        (key,) = initPoolAndAddLiquidity(currency0, currency1, hooks, FEE, SQRT_PRICE_1_1, ZERO_BYTES);
        nestedActionRouter.executor().setKey(key);
        (nativeKey,) = initPoolAndAddLiquidityETH(
            CurrencyLibrary.ADDRESS_ZERO, currency1, hooks, FEE, SQRT_PRICE_1_1, ZERO_BYTES, 1 ether
        );
        uninitializedKey = key;
        uninitializedNativeKey = nativeKey;
        uninitializedKey.fee = 100;
        uninitializedNativeKey.fee = 100;
    }
}
