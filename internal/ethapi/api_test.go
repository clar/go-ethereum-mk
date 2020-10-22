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

func TestDataDecode(t *testing.T) {
	parsed, err := abi.JSON(strings.NewReader(mkEnterRawABI))
	if err != nil {
		panic(err)
	}

	data, _ := hex.DecodeString("ee682473000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000005b22bb54b67c800000000000000000000000000000000000000000000000000000000000000e4d470470f000000000000000000000000c4ed1b3f31acadbe3c14b20fa766b6c4b1fab20800000000000000000000000074437d785fc00a31bfd35d06588bd9b2b8a03c7d00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044fdd54ba100000000000000000000000074437d785fc00a31bfd35d06588bd9b2b8a03c7d000000000000000000000000047b05e7628ec657a2877db844896861fbe68c3a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041c4d82728a90700b3a3939d738730b3b5f32b690a8449b7b5c470249dbb8881a971cf8da2f82ba209c9e79adf8048d4be3cda4cc2dc2ec409c26f2e9fe6d136201c00000000000000000000000000000000000000000000000000000000000000")
	// data, _ := hex.DecodeString("ee682473000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001a00000000000000000000000000000000000000000000000000005b239343051180000000000000000000000000000000000000000000000000000000000000104fd6ac309000000000000000000000000082794c605b82ed8ff6fedffe2087c55f4ebd5d60000000000000000000000001c21bdaf794de6d1eae3bbd419145eb8388666c9000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000044095ea7b300000000000000000000000074437d785fc00a31bfd35d06588bd9b2b8a03c7d00000000000000000000000000000000000000000000000000000000009896800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004117f0efba64057cf086561d1cbad4bb89df6e53b645850f6ab24f343cc390832056eacbfb2ca1939fd70f374130d98363c5944a0d18ee967b52e40d375c2688f81b00000000000000000000000000000000000000000000000000000000000000")

	var inputs struct {
		Data      []byte
		Signature []byte
		Nonce     *big.Int
	}
	// fmt.Println("data", data[:4])

	err = parsed.Methods["enter"].Inputs.Unpack(&inputs, data[4:])

	if err != nil {
		panic(err)
		return
	}

	addr := common.BytesToAddress(inputs.Data[4:36])
	addr2 := common.BytesToAddress(inputs.Data[36 : 36+32])
	// copy(actionId[:], inputs.Data[0:4])
	actionId := inputs.Data[0:4]
	fmt.Println("addr", addr.Hex())
	fmt.Println("addr2", addr2.Hex())
	fmt.Println("actionId", actionId)
	fmt.Println("actionId", hex.EncodeToString(actionId))

	fmt.Println(crypto.Keccak256([]byte("proposeAsBackup(address,address,bytes)"))[:4])
	fmt.Println(hex.EncodeToString(crypto.Keccak256([]byte("proposeAsBackup(address,address,bytes)"))[:4]))
}

func TestHash(t *testing.T) {
	fmt.Println(crypto.Keccak256([]byte("proposeAsBackup(address,address,bytes)"))[:4])
	fmt.Println(hex.EncodeToString(crypto.Keccak256([]byte("proposeAsBackup(address,address,bytes)"))[:4]))
}
