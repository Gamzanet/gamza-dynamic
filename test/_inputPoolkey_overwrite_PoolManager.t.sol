// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console, stdStorage, StdStorage} from "forge-std/Test.sol";
import {IHooks} from "../src/interfaces/IHooks.sol";
import {Hooks} from "../src/libraries/Hooks.sol";
import {IPoolManager} from "../src/interfaces/IPoolManager.sol";
import {IProtocolFees} from "../src/interfaces/IProtocolFees.sol";
import {IProtocolFeeController} from "../src/interfaces/IProtocolFeeController.sol";
import {PoolManager} from "../src/PoolManager.sol";
import {TickMath} from "../src/libraries/TickMath.sol";
import {Pool} from "../src/libraries/Pool.sol";
import {Deployers} from "./utils/Deployers.sol";
import {Currency, CurrencyLibrary} from "../src/types/Currency.sol";
import {MockHooks} from "../src/test/MockHooks.sol";
import {MockContract} from "../src/test/MockContract.sol";
import {EmptyTestHooks} from "../src/test/EmptyTestHooks.sol";
import {PoolKey} from "../src/types/PoolKey.sol";
import {PoolModifyLiquidityTest} from "../src/test/PoolModifyLiquidityTest.sol";
import {BalanceDelta, BalanceDeltaLibrary} from "../src/types/BalanceDelta.sol";
import {PoolSwapTest} from "../src/test/PoolSwapTest.sol";
import {TestInvalidERC20} from "../src/test/TestInvalidERC20.sol";
import {GasSnapshot} from "forge-gas-snapshot/GasSnapshot.sol";
import {PoolEmptyUnlockTest} from "../src/test/PoolEmptyUnlockTest.sol";
import {Action} from "../src/test/PoolNestedActionsTest.sol";
import {PoolId} from "../src/types/PoolId.sol";
import {LPFeeLibrary} from "../src/libraries/LPFeeLibrary.sol";
import {Position} from "../src/libraries/Position.sol";
import {Constants} from "./utils/Constants.sol";
import {SafeCast} from "../src/libraries/SafeCast.sol";
import {AmountHelpers} from "./utils/AmountHelpers.sol";
import {ProtocolFeeLibrary} from "../src/libraries/ProtocolFeeLibrary.sol";
import {IProtocolFees} from "../src/interfaces/IProtocolFees.sol";
import {StateLibrary} from "../src/libraries/StateLibrary.sol";
import {Actions} from "../src/test/ActionsRouter.sol";

contract PoolManagerTest is Test, Deployers, GasSnapshot {
    using Hooks for IHooks;
    using LPFeeLibrary for uint24;
    using SafeCast for *;
    using ProtocolFeeLibrary for uint24;
    using StateLibrary for IPoolManager;

    using stdStorage for StdStorage;


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
    PoolKey inputkey;
    function setUp() public {
        // string memory code_json = vm.readFile("test/_json_GasPriceFeesHook.json");
        // string memory code_json = vm.readFile("test/_json_PointsHook.json");
        // string memory code_json = vm.readFile("test/_json_TakeProfitsHook.json");

        // bytes memory currency0Bytes = vm.parseJsonBytes(code_json, ".data.currency0");
        // bytes memory currency1Bytes = vm.parseJsonBytes(code_json, ".data.currency1");
        // bytes memory hooksBytes = vm.parseJsonBytes(code_json, ".data.hooks");

        // inputkey.currency0 = abi.decode(currency0Bytes, (address));
        // inputkey.currency1 = abi.decode(currency1Bytes, (address));
        // inputkey.fee = uint24(vm.parseJsonUint(code_json, ".data.fee"));
        // inputkey.tickSpacing = int24(vm.parseJsonInt(code_json, ".data.tickSpacing"));
        // inputkey.hooks = abi.decode(hooksBytes, (address));

        inputkey.fee = Constants.FEE_MEDIUM;
        // inputkey.fee = LPFeeLibrary.DYNAMIC_FEE_FLAG;
        inputkey.tickSpacing = 60;
        inputkey.hooks = IHooks(0x7dFCe7A9Cc9E6Cfa35a3aBf0079988b58dD15040);

        (bool success, bytes memory returnData) = address(inputkey.hooks).call(abi.encodeWithSignature("getHookPermissions()"));
        flag = abi.decode(returnData, (Hooks.Permissions));

        hookAddr = address(inputkey.hooks);

        initializeManagerRoutersAndPoolsWithLiq(IHooks(address(0)));

        // FEE = LPFeeLibrary.DYNAMIC_FEE_FLAG;
        FEE = Constants.FEE_MEDIUM;
        
        // vm.mockCall을 사용해 poolManager() 호출을 모킹
        // vm.mockCall(
        //     address(hookAddr),  // 모킹할 컨트랙트 주소
        //     abi.encodeWithSignature("poolManager()"),  // 모킹할 함수 시그니처
        //     abi.encode(address(manager))  // 반환할 값 (모킹된 값)
        // );

        stdstore
            .target(address(hookAddr))
            .sig("poolManager()")
            .checked_write(address(manager));

        // address(hookAddr).call(abi.encodeWithSignature("poolManager()"));
    }

    function test_initialize_succeedsWithHooks(uint160 sqrtPriceX96) public {
        if (!flag.beforeInitialize && !flag.afterInitialize) {
            emit log_string("Skip Test");
            return;
        }
        sqrtPriceX96 = uint160(bound(sqrtPriceX96, TickMath.MIN_SQRT_PRICE, TickMath.MAX_SQRT_PRICE - 1));

        address payable mockAddr = payable(address(uint160(address(hookAddr)) ^ 0x10000000));

        MockContract mockContract = new MockContract();
        vm.etch(mockAddr, address(mockContract).code);

        MockContract(mockAddr).setImplementation(hookAddr);

        (key,) = initPool(currency0, currency1, IHooks(mockAddr), FEE, sqrtPriceX96, ZERO_BYTES);
    }

    function test_addLiquidity_succeedsWithHooksIfInitialized(uint160 sqrtPriceX96) public {
        if (!flag.beforeAddLiquidity && !flag.afterAddLiquidity) {
            emit log_string("Skip Test");
            return;
        }
        sqrtPriceX96 = uint160(bound(sqrtPriceX96, TickMath.MIN_SQRT_PRICE, TickMath.MAX_SQRT_PRICE - 1));

        address payable mockAddr = payable(address(uint160(address(hookAddr)) | 0x10000000));

        MockContract mockContract = new MockContract();
        vm.etch(mockAddr, address(mockContract).code);

        MockContract(mockAddr).setImplementation(hookAddr);

        (key,) = initPool(currency0, currency1, IHooks(mockAddr), FEE, sqrtPriceX96, ZERO_BYTES);

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

        address payable mockAddr = payable(address(uint160(address(hookAddr)) | 0x10000000));

        MockContract mockContract = new MockContract();
        vm.etch(mockAddr, address(mockContract).code);

        MockContract(mockAddr).setImplementation(hookAddr);

        (key,) = initPool(currency0, currency1, IHooks(mockAddr), FEE, sqrtPriceX96, ZERO_BYTES);
        
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
        address payable mockAddr = payable(address(uint160(address(hookAddr)) | 0x10000000));
        MockHooks impl = new MockHooks();
        vm.etch(mockAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(mockAddr);
        
        (key,) = initPool(currency0, currency1, mockHooks, FEE, SQRT_PRICE_1_1, ZERO_BYTES);

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
        address payable mockAddr = payable(address(uint160(address(hookAddr)) | 0x10000000));
        MockHooks impl = new MockHooks();
        vm.etch(mockAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(mockAddr);

        (key,) = initPool(currency0, currency1, mockHooks, FEE, SQRT_PRICE_1_1, ZERO_BYTES);
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
        address payable mockAddr = payable(address(uint160(address(hookAddr)) | 0x10000000));
        MockHooks impl = new MockHooks();
        vm.etch(mockAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(mockAddr);

        (key,) = initPool(currency0, currency1, mockHooks, FEE, SQRT_PRICE_1_1, ZERO_BYTES);

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
        address payable mockAddr = payable(address(uint160(address(hookAddr)) | 0x10000000));
        MockHooks impl = new MockHooks();
        vm.etch(mockAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(mockAddr);

        (key,) = initPool(currency0, currency1, mockHooks, FEE, SQRT_PRICE_1_1, ZERO_BYTES);
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

    function test_addLiquidity_withHooks_gas() public {
        if (!flag.beforeAddLiquidity && !flag.afterAddLiquidity) {
            emit log_string("Skip Test");
            return;
        }
        address payable mockAddr = payable(address(uint160(address(hookAddr)) | 0x10000000));
        MockHooks impl = new MockHooks();
        vm.etch(mockAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(mockAddr);

        (key,) = initPool(currency0, currency1, mockHooks, FEE, SQRT_PRICE_1_1, ZERO_BYTES);

        modifyLiquidityRouter.modifyLiquidity(key, LIQUIDITY_PARAMS, ZERO_BYTES);
        snapLastCall("addLiquidity with empty hook");
    }

    function test_removeLiquidity_withHooks_gas() public {
        if (!flag.beforeRemoveLiquidity && !flag.afterRemoveLiquidity) {
            emit log_string("Skip Test");
            return;
        }
        address payable mockAddr = payable(address(uint160(address(hookAddr)) | 0x10000000));
        MockHooks impl = new MockHooks();
        vm.etch(mockAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(mockAddr);

        (key,) = initPool(currency0, currency1, mockHooks, FEE, SQRT_PRICE_1_1, ZERO_BYTES);
        modifyLiquidityRouter.modifyLiquidity(key, LIQUIDITY_PARAMS, ZERO_BYTES);

        modifyLiquidityRouter.modifyLiquidity(key, REMOVE_LIQUIDITY_PARAMS, ZERO_BYTES);
        snapLastCall("removeLiquidity with empty hook");
    }

    function test_swap_succeedsWithHooksIfInitialized() public {
        if (!flag.beforeSwap && !flag.afterSwap) {
            emit log_string("Skip Test");
            return;
        }
        address payable mockAddr = payable(address(uint160(address(hookAddr)) | 0x10000000));

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
        address payable mockAddr = payable(address(uint160(address(hookAddr)) | 0x10000000));
        MockHooks impl = new MockHooks();
        vm.etch(mockAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(mockAddr);

        (key,) = initPoolAndAddLiquidity(currency0, currency1, mockHooks, FEE, SQRT_PRICE_1_1, ZERO_BYTES);

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
        address payable mockAddr = payable(address(uint160(address(hookAddr)) | 0x10000000));
        MockHooks impl = new MockHooks();
        vm.etch(mockAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(mockAddr);

        (key,) = initPoolAndAddLiquidity(currency0, currency1, mockHooks, FEE, SQRT_PRICE_1_1, ZERO_BYTES);

        IPoolManager.SwapParams memory swapParams =
            IPoolManager.SwapParams({zeroForOne: true, amountSpecified: -10, sqrtPriceLimitX96: SQRT_PRICE_1_2});

        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: true, settleUsingBurn: false});

        mockHooks.setReturnValue(mockHooks.beforeSwap.selector, mockHooks.beforeSwap.selector);
        mockHooks.setReturnValue(mockHooks.afterSwap.selector, mockHooks.afterSwap.selector);

        // vm.expectEmit(true, true, true, true);
        // emit Swap(key.toId(), address(swapRouter), -10, 8, 79228162514264336880490487708, 1e18, -1, 100);

        swapRouter.swap(key, swapParams, testSettings, ZERO_BYTES);
    }

    function test_swap_withHooks_gas() public {
        if (!flag.beforeSwap && !flag.afterSwap) {
            emit log_string("Skip Test");
            return;
        }
        address payable mockAddr = payable(address(uint160(address(hookAddr)) | 0x10000000));
        MockHooks impl = new MockHooks();
        vm.etch(mockAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(mockAddr);

        (key,) = initPoolAndAddLiquidity(currency0, currency1, mockHooks, FEE, SQRT_PRICE_1_1, ZERO_BYTES);

        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});

        swapRouter.swap(key, SWAP_PARAMS, testSettings, ZERO_BYTES);

        IPoolManager.SwapParams memory swapParams =
            IPoolManager.SwapParams({zeroForOne: true, amountSpecified: -100, sqrtPriceLimitX96: SQRT_PRICE_1_4});
        testSettings = PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});

        swapRouter.swap(key, swapParams, testSettings, ZERO_BYTES);
        snapLastCall("swap with hooks");
    }

    function test_donate_failsWithIncorrectSelectors() public {
        if (!flag.beforeDonate && !flag.afterDonate) {
            emit log_string("Skip Test");
            return;
        }
        address payable mockAddr = payable(address(uint160(address(hookAddr)) | 0x10000000));
        MockHooks impl = new MockHooks();
        vm.etch(mockAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(mockAddr);

        (key,) = initPoolAndAddLiquidity(currency0, currency1, mockHooks, FEE, SQRT_PRICE_1_1, ZERO_BYTES);

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
        address payable mockAddr = payable(address(uint160(address(hookAddr)) | 0x10000000));
        MockHooks impl = new MockHooks();
        vm.etch(mockAddr, address(impl).code);
        MockHooks mockHooks = MockHooks(mockAddr);

        (key,) = initPoolAndAddLiquidity(currency0, currency1, mockHooks, FEE, SQRT_PRICE_1_1, ZERO_BYTES);

        mockHooks.setReturnValue(mockHooks.beforeDonate.selector, mockHooks.beforeDonate.selector);
        mockHooks.setReturnValue(mockHooks.afterDonate.selector, mockHooks.afterDonate.selector);

        donateRouter.donate(key, 100, 200, ZERO_BYTES);
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
}
