/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sm2

import (
	"crypto/rand"
	"fmt"
	"github.com/CloudmindsRobot/gmgo/crypto/internal/sm3"
	"io/ioutil"
	"os"
	"testing"
)

func TestSm2(t *testing.T) {
	priv, err := GenerateKey() // 生成密钥对
	fmt.Println(priv)
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}

	fmt.Printf("%v\n", priv.Curve.IsOnCurve(priv.X, priv.Y)) // 验证是否为sm2的曲线
	pub := &priv.PublicKey
	msg := []byte("123456")
	d0, err := pub.Encrypt(msg)
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}

	// fmt.Printf("Cipher text = %v\n", d0)
	d1, err := priv.Decrypt(d0)
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}
	fmt.Printf("clear text = %s\n", d1)

	msg, _ = ioutil.ReadFile("ifile")             // 从文件读取数据
	sign, err := priv.Sign(rand.Reader, msg, nil) // 签名
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}

	err = ioutil.WriteFile("TestResult", sign, os.FileMode(0644))
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}
	signdata, _ := ioutil.ReadFile("TestResult")
	ok := priv.Verify(msg, signdata) // 密钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
		t.Fatalf("err = Verify error")
		return
	} else {
		fmt.Printf("Verify ok\n")
	}
	pubKey := priv.PublicKey
	ok = pubKey.Verify(msg, signdata) // 公钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
		t.Fatalf("err = Verify error")
		return
	} else {
		fmt.Printf("Verify ok\n")
	}

}

func TestSm2Pkg(t *testing.T) {
	data := "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"

	priv, err := GenerateKey() // 生成密钥对
	fmt.Println(priv)
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}

	fmt.Printf("%v\n", priv.Curve.IsOnCurve(priv.X, priv.Y)) // 验证是否为sm2的曲线
	pub := &priv.PublicKey

	hash1 := sm3.Sm3Sum([]byte(data))
	r, s, err := Sign(priv, hash1)
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}

	bVerify := Verify(pub, hash1, r, s)
	if !bVerify {
		t.Fatalf("bVerify = %v", bVerify)
		return
	}
}

func BenchmarkSM2(t *testing.B) {
	t.ReportAllocs()
	msg := []byte("test")
	priv, err := GenerateKey() // 生成密钥对
	if err != nil {
		t.Fatalf("err = %v", err)
		return
	}

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sign, err := priv.Sign(nil, msg, nil) // 签名
		if err != nil {
			t.Fatalf("err = %v", err)
			return
		}
		priv.Verify(msg, sign) // 密钥验证
	}
}
