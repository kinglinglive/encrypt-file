# encrypt-file
文件AES加密

## 编译
linux
```
go build -o king-encrypt main.go
```

windows
```
go build -o king-encrypt.exe main.go
```

## 示例
加密
```
king-encrypt.exe 密钥 文件 [加密后的文件名]
```

解密
```
king-encrypt.exe -d 密钥 已加密的文件 解密后的文件名
```
