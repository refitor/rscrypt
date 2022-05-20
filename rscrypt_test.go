package rscrypto

import (
	"reflect"
	"testing"
)

func TestGenerateEcdsaKey(t *testing.T) {
	tests := []struct {
		name    string
		want    []byte
		want1   []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := GenerateEcdsaKey()
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateEcdsaKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateEcdsaKey() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("GenerateEcdsaKey() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestGetSharedKey(t *testing.T) {
	type args struct {
		private []byte
		public  []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetSharedKey(tt.args.private, tt.args.public)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSharedKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetSharedKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEcdsaSign(t *testing.T) {
	type args struct {
		origData   []byte
		privateKey []byte
	}
	tests := []struct {
		name                 string
		args                 args
		wantSignature_encode string
		wantErr              bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSignature_encode, err := EcdsaSign(tt.args.origData, tt.args.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("EcdsaSign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotSignature_encode != tt.wantSignature_encode {
				t.Errorf("EcdsaSign() = %v, want %v", gotSignature_encode, tt.wantSignature_encode)
			}
		})
	}
}

func TestEcdsaVerify(t *testing.T) {
	type args struct {
		origData  string
		signature string
		publicKey []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := EcdsaVerify(tt.args.origData, tt.args.signature, tt.args.publicKey); (err != nil) != tt.wantErr {
				t.Errorf("EcdsaVerify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEcdsaEncrypt(t *testing.T) {
	type args struct {
		origData  []byte
		publicKey []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EcdsaEncrypt(tt.args.origData, tt.args.publicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("EcdsaEncrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EcdsaEncrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEcdsaDecrypt(t *testing.T) {
	type args struct {
		ciphertext []byte
		privateKey []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EcdsaDecrypt(tt.args.ciphertext, tt.args.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("EcdsaDecrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EcdsaDecrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateRsaKey(t *testing.T) {
	tests := []struct {
		name    string
		want    []byte
		want1   []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := GenerateRsaKey()
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateRsaKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateRsaKey() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("GenerateRsaKey() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestRsaEncrypt(t *testing.T) {
	type args struct {
		origData  []byte
		publicKey []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RsaEncrypt(tt.args.origData, tt.args.publicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("RsaEncrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RsaEncrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRsaDecrypt(t *testing.T) {
	type args struct {
		ciphertext []byte
		privateKey []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RsaDecrypt(tt.args.ciphertext, tt.args.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("RsaDecrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RsaDecrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRsaSign(t *testing.T) {
	type args struct {
		origData   []byte
		privateKey []byte
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RsaSign(tt.args.origData, tt.args.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("RsaSign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("RsaSign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRsaVerify(t *testing.T) {
	type args struct {
		origData  []byte
		signature []byte
		publicKey []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := RsaVerify(tt.args.origData, tt.args.signature, tt.args.publicKey); (err != nil) != tt.wantErr {
				t.Errorf("RsaVerify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateAesKey(t *testing.T) {
	type args struct {
		data string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GenerateAesKey(tt.args.data); got != tt.want {
				t.Errorf("GenerateAesKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAesEncryptECB(t *testing.T) {
	type args struct {
		origData []byte
		key      []byte
	}
	tests := []struct {
		name          string
		args          args
		wantEncrypted []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotEncrypted := AesEncryptECB(tt.args.origData, tt.args.key); !reflect.DeepEqual(gotEncrypted, tt.wantEncrypted) {
				t.Errorf("AesEncryptECB() = %v, want %v", gotEncrypted, tt.wantEncrypted)
			}
		})
	}
}

func TestAesDecryptECB(t *testing.T) {
	type args struct {
		encrypted []byte
		key       []byte
	}
	tests := []struct {
		name          string
		args          args
		wantDecrypted []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotDecrypted := AesDecryptECB(tt.args.encrypted, tt.args.key); !reflect.DeepEqual(gotDecrypted, tt.wantDecrypted) {
				t.Errorf("AesDecryptECB() = %v, want %v", gotDecrypted, tt.wantDecrypted)
			}
		})
	}
}

func Test_generateKey(t *testing.T) {
	type args struct {
		key []byte
	}
	tests := []struct {
		name       string
		args       args
		wantGenKey []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotGenKey := generateKey(tt.args.key); !reflect.DeepEqual(gotGenKey, tt.wantGenKey) {
				t.Errorf("generateKey() = %v, want %v", gotGenKey, tt.wantGenKey)
			}
		})
	}
}
