package ethapi

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const RawABI = `[
  {
    "constant": false,
    "inputs": [
      {
        "name": "_data",
        "type": "bytes"
      },
      {
        "name": "_signature",
        "type": "bytes"
      },
      {
        "name": "_nonce",
        "type": "uint256"
      }
    ],
    "name": "enter",
    "outputs": [],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  }
]
`

func decodeTxData(abi *abi.ABI, txData []byte, result interface{}) (err error) {
	if len(txData) < 4 || len(txData)%32 != 4 {
		return fmt.Errorf("error length of data: %v", len(txData))
	}
	m, err := abi.MethodById(txData[:4])
	if err != nil {
		return
	}
	err = m.Inputs.Unpack(result, txData[4:])
	if err != nil {
		return
	}
	return
}

func TestDecodeLogicEnter(t *testing.T) {

	parsed, err := abi.JSON(strings.NewReader(RawABI))
	if err != nil {
		panic(err)
	}

	var inputs struct {
		Data      []byte
		Signature []byte
		Nonce     *big.Int
	}

	txInput := "0xee682473000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000005b1889ad71f6200000000000000000000000000000000000000000000000000000000000000841934741b000000000000000000000000e9f7c45595f1ebc7c4756e20aed1ea2e9ac65195000000000000000000000000f5b0873c55a2a2277a77f42db2b473145b747749000000000000000000000000431ad2ff6a9c365805ebad47ee021148d6f7dbe00000000000000000000000000000000000000000000000977a935fe75ce46b3a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041620e4c50958b8c796fe045152e62776b6ec3523ad152f54880fe78de89b8bb364ac56ff7001708317d74f741563539b5de226341d24a44b73e881c2b0f2543f61b00000000000000000000000000000000000000000000000000000000000000"
	decodedData, _ := hex.DecodeString(txInput[10:])

	err = parsed.Methods["enter"].Inputs.Unpack(&inputs, decodedData)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(hex.EncodeToString(inputs.Data))

	addr := common.BytesToAddress(inputs.Data[4:36])
	fmt.Println(addr.Hex())
}

func TestMkAccountStorageGetStorageAt(t *testing.T) {

	// AccountStorage
	// slot 0 - mapping (address => uint256) operationKeyCount;
	// 		slot =  mappingValueSlotUint256(0, address)
	//
	// slot 1 - mapping (address => mapping(uint256 => KeyItem)) keyData;
	//      keyIndex = 0
	//      slotTemp =  mappingValueSlotUint256(1, address)
	//      slot = mappingValueSlotUint256(slotTemp, keyIndex)

	// mappingValueSlotUint256(slot, key)
	// 		bytes memory slotEncoded  = abi.encodePacked((uint256)key,(uint256)slot);
	// 		return keccak256(slotEncoded);

	slotTemp := crypto.Keccak256Hash(
		common.HexToAddress("0xc4ED1B3f31acadbE3c14B20fA766B6C4B1FAB208").Hash().Bytes(), // address to 32 bytes
		common.LeftPadBytes(big.NewInt(1).Bytes(), 32),                                   // slot 1
	)

	fmt.Println(slotTemp.Hex())

	adminKeyQueryhash := crypto.Keccak256Hash(
		common.LeftPadBytes(big.NewInt(0).Bytes(), 32),
		slotTemp.Bytes(),
	)

	fmt.Println("adminKeyQueryhash", adminKeyQueryhash.Hex())

	transferKeyQueryhash := crypto.Keccak256Hash(
		common.LeftPadBytes(big.NewInt(1).Bytes(), 32),
		slotTemp.Bytes(),
	)

	fmt.Println("transferKeyQueryhash", transferKeyQueryhash.Hex())

	reservedKeyQueryhash := crypto.Keccak256Hash(
		common.LeftPadBytes(big.NewInt(3).Bytes(), 32),
		slotTemp.Bytes(),
	)

	fmt.Println("reservedKeyQueryhash", reservedKeyQueryhash.Hex())

	// let storageAddr="0x6185Dd4709982c03750e03FA8b3fF30D042585b9"
	// let userAddr="0xc4ED1B3f31acadbE3c14B20fA766B6C4B1FAB208"

	// mappingValueSlotUint256(1, "0xc4ED1B3f31acadbE3c14B20fA766B6C4B1FAB208") = 0x2c2f5784f0ab958c991982f727cc4c82ef6903601b2ae61dc4c528ce8f86ed71
	// mappingValueSlotUint256(0x2c2f5784f0ab958c991982f727cc4c82ef6903601b2ae61dc4c528ce8f86ed71, 0) = 0x3ef4195804bad0736532041673363afaf8c8a8ccf27c40df4929d9eeba52b05c
	// getStorageAt(storageAddr, 0x3ef4195804bad0736532041673363afaf8c8a8ccf27c40df4929d9eeba52b05c) = 0x000000000000000000000000822d3aff3881f3ec320f63a3f5047eb12d2c0ad9

}
