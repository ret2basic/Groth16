// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {Pairing} from "../src/VerifierPairingCheck.sol";

contract PairingTest is Test {

    Pairing public pairing;

    function setUp() public {
        pairing = new Pairing();
    }

    function test_pairing() public {
        assertTrue(pairing.verifier());
    }
}
