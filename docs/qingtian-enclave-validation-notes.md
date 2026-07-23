# QingTian Enclave Validation Notes

本文记录 `proof-of-observation` 从 AWS Nitro Enclave 迁移到 Huawei Cloud QingTian Enclave 前的机器验证、smoke test、attestation 样本采集和后续改造依据。

记录日期：2026-07-20  
有效机器：`ansible@shihuo-enclave-hw02`  
宿主机系统：Huawei Cloud EulerOS 2.0  

## 结论

当前信息已经足够进入 `proof-of-observation` 的 QingTian Enclave 代码改造阶段。

已验证通过：

- 支持 Enclave 的 HCE 2.0 父虚机可以启动 QingTian Enclave。
- `qt enclave make-img` 可以从 Docker image 生成 EIF 并输出 PCR。
- debug 模式 hello enclave 可以启动并通过 console 观察输出。
- normal / production 模式 enclave 可以启动。
- enclave 内 QTSM 设备可用，`qtsm_get_attestation` 可以生成 attestation document。
- 非 debug 模式下，可以通过 vsock 将 attestation document 回传到父虚机。
- 已取得可解码的 production attestation 样本。
- 已使用华为官方 `make-img --private-key --signing-certificate` 路径生成可启动的 signed EIF，`PCR8` 为非 0。
- 已取得绑定真实 Ed25519 SPKI DER public key 和 32 字节 nonce 的 QingTian QTSM fixture，并在 Node verifier 中完成证书链、COSE 签名、PCR0/PCR8、公钥和 nonce 校验。
- 已从华为官方“密码学证明/签名验证”文档确认 QingTian attestation trust anchor 获取方式，并校验 root 证书 zip hash 与 root fingerprint。
- 已从 Gitee QingTian SDK 源码确认 QTSM API、字段长度上限、`/dev/qtsm` 设备路径和 parent CID 默认值。

仍属于生产化决策/实现点：

- 早期 production smoke 样本使用 placeholder pubkey 且未签名 EIF，只能作为链路 smoke；后续 verifier 正例应优先使用 official-signed fixture。
- 生产发布需要固定官方 release signed EIF 的 Docker image digest、EIF digest、PCR0/PCR8 和 release manifest 签名。
- verifier 需要为每个发布版配置固定的 QingTian root fingerprint、可选 intermediate fingerprint 和 PCR allowlist。
- 真实业务镜像构建后，需要重新采集并发布对应 `PCR0`。

## 官方文档要点

创建 QingTian Enclave 父虚机时，需要在 ECS 创建流程中勾选 Enclave 能力。Huawei Cloud EulerOS 2.0 是官方推荐的父虚机系统之一。

本次使用/校准过的官方入口：

- QingTian Enclave 应用开发主入口：`https://support.huaweicloud.com/usermanual-ecs/ecs_03_1414.html`
- 密码学证明：`https://support.huaweicloud.com/usermanual-ecs/ecs_03_1411.html`
- 签名验证：`https://support.huaweicloud.com/usermanual-ecs/ecs_03_1412.html`
- QingTian SDK Gitee：`https://gitee.com/HuaweiCloudDeveloper/huawei-qingtian/tree/master/enclave`

官方文档与 SDK 对当前实现的关键结论：

- QingTian attestation document 由 enclave 内 QTSM 生成，父虚机 Docker 容器内没有 `/dev/qtsm`，不能在普通容器里取得真实 attestation。
- QTSM attestation document 是 COSE/CBOR 结构，payload 包含 `module_id`、`timestamp`、`digest`、`pcrs`、`certificate`、`cabundle`、`user_data`、`nonce`、`public_key`。
- QTSM COSE protected header 已在真实样本中确认为 ES384 / `-35`，payload digest 为 `SHA384`。
- QingTian app 与父虚机通信使用 vsock；官方 qproxy 和 Rust SDK 中 parent CID 默认值为 `3`，enclave CID 示例常用 `4`。
- `qt enclave make-img` 可以在生成 EIF 时直接传 `--private-key` 和 `--signing-certificate`，这是当前已验证可启动 signed EIF 的路径。

Huawei QingTian attestation root：

```text
官方 root zip: https://qingtian-enclave.obs.myhuaweicloud.com/huawei_qingtian-enclaves_root-G1.zip
zip sha256:   99e9203a64cfb0c6495afd815051e97bea8a37895dc083d715674af64adeadfe
root subject: C=CN, ST=Guizhou, L=Guiyang, O=Huawei Technologies, OU=Huawei Cloud, CN=huaweicloud.qingtian-enclaves
root notAfter: 2052-09-30 09:22:56 GMT
root fingerprint sha256:
F23443B4EB52A70719DF49BDDA0E57BB25F1C04530885DBECDBDE241C8C4F581
```

生产 verifier 的 `platformTrust.rootFingerprintsSha256` 应 pin 上述 root fingerprint。下载 root zip 时必须先校验 zip sha256，再从 `root.pem` 计算 fingerprint。

`PCR8` 与 EIF 签名证书相关：

- 未签名 EIF：`PCR8` 为全 0。
- 签名 EIF：`PCR8` 由签名证书度量得到。
- 同一份 `server.pem` 对应的 `PCR8` 可跨机器保持一致。
- `private-key.pem` 必须与 `server.pem` 匹配；不能用不匹配的私钥给同一个证书签名。

建议第三方中转站部署模式：

1. 项目方开源源码。
2. 项目方 CI/CD 构建官方 Docker image。
3. 项目方使用发布私钥和发布证书签名生成官方 EIF。
4. 发布 EIF、Docker image digest、PCR0、PCR8、release manifest 和 manifest 签名。
5. 第三方中转站直接部署官方 signed EIF，不持有签名私钥。

这样不同中转站部署相同 EIF 时，`PCR0/PCR8` 能保持一致。

## 宿主机基础验证

基础信息：

```bash
hostname
date
cat /etc/os-release
uname -a
lscpu | grep -E 'Architecture|CPU\(s\)|Model name|NUMA'
free -h
curl -s http://169.254.169.254/latest/meta-data/instance-id || true
curl -s http://169.254.169.254/latest/meta-data/instance-type || true
```

安装/确认 QingTian 组件：

```bash
sudo yum install -y qt-enclave-bootstrap virtio-qtbox qingtian-tool
rpm -qa | grep -Ei 'qt-enclave|qingtian|qtbox|virtio'
which qt
qt enclave -h
```

安装 Docker：

```bash
sudo yum install -y docker-engine
sudo systemctl enable --now docker
docker version
docker ps
```

如果普通用户没有 Docker 权限：

```bash
sudo usermod -aG docker ansible
newgrp docker
docker ps
```

配置华为云 SWR DockerHub 镜像加速后，`docker pull busybox:latest` 成功：

```text
Registry Mirrors:
 https://14963ae052ba40568844a37df1157b46.mirror.swr.myhuaweicloud.com/
```

Docker 版本：

```text
Docker 18.09.0
API version 1.39
OS/Arch linux/amd64
```

该版本已验证足够支持当前 `qt enclave make-img` smoke 链路。

## qt 权限问题

普通用户执行 `qt` 可能遇到：

```text
qt enclave logger: log file exists but has no permission
log file path is /var/log/qingtian_enclaves/qingtian-tool.log
```

原因通常是之前执行过 `sudo qt ...`，导致日志文件被 root 创建或改写。修复：

```bash
sudo mkdir -p /var/run/enclave /var/log/qingtian_enclaves
sudo chown -R ansible:ansible /var/run/enclave /var/log/qingtian_enclaves
sudo chmod 755 /var/run/enclave /var/log/qingtian_enclaves
sudo chmod 644 /var/log/qingtian_enclaves/qingtian-tool.log 2>/dev/null || true
```

建议：

- `make-img/query/start/stop` 尽量使用普通 `ansible` 用户。
- debug console 因 `/dev/sandbox-log-0` 权限问题可能需要 `sudo qt enclave console --enclave-id 0`。
- 每次使用 `sudo qt` 后，如果普通 `qt` 再次报日志权限，重新执行上面的 `chown`。

如果 `sudo qt` 报：

```text
ModuleNotFoundError: No module named 'docker'
```

说明 root Python 环境缺依赖：

```bash
sudo env python -m pip install docker knack
sudo env python -c 'import docker, knack; print("root python deps ok")'
```

## hello enclave 验证

构建 hello 镜像：

```bash
mkdir -p ~/qt-enclave-hello
cd ~/qt-enclave-hello

cat > hello_enclave.sh <<'EOF'
#!/bin/bash
while true
do
    echo "hello enclave!"
    sleep 2
done
EOF

chmod +x hello_enclave.sh

cat > Dockerfile <<'EOF'
FROM ubuntu:22.04
COPY hello_enclave.sh /root/hello_enclave.sh
CMD ["/root/hello_enclave.sh"]
EOF

docker build --no-cache -f Dockerfile -t hello-enclave .
```

生成 EIF：

```bash
qt enclave make-img --docker-uri hello-enclave --eif hello-enclave.eif
```

有效输出：

```text
digest: SHA384
PCR0: 32a59343a9b931aa088050094e5e33424f563075931c2877e4455fcf02ce25e2f997171d7f08ecc7823a9962c1cc2954
PCR8: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

启动 debug enclave：

```bash
qt enclave start --mem 1024 --cpus 2 --eif hello-enclave.eif --cid 4 --debug-mode
qt enclave query
sudo qt enclave console --enclave-id 0
```

关键成功日志：

```text
QTSM driver version = 1.0.3.
QTSM device has been probed.
Heartbeat and time synchronization success
Begin to run '/root/hello_enclave.sh'
hello enclave!
```

非 debug 模式也已验证可启动并查询：

```bash
qt enclave start --mem 1024 --cpus 2 --eif hello-enclave.eif --cid 4
qt enclave query
qt enclave stop --enclave-id 0
```

## QingTian SDK 来源

GitHub 上的 `https://github.com/huaweicloud/huawei-qingtian.git` 是空壳，不包含 `enclave/qtsm`。

使用 Gitee 官方仓库：

```bash
cd ~/qt-attest-smoke
git clone https://gitee.com/HuaweiCloudDeveloper/huawei-qingtian.git

ls -la huawei-qingtian/enclave/qtsm
ls -la huawei-qingtian/enclave/qtsm/include
ls -la huawei-qingtian/enclave/qtsm/lib
```

本次本地校准使用的 Gitee commit：

```text
516a3f4531d0ff6cbde6e19764fb6319650b9fc5
```

仓库顶层和 `enclave/qtsm` 均为 Apache-2.0 许可。开源项目可以选择 vendoring SDK，或在发布流水线中下载并校验 commit/tarball hash；无论哪种方式，release manifest 都应记录 SDK commit 或 tarball hash。

当前 Gitee SDK 的 `qtsm_get_attestation` API 形式为：

```c
int qtsm_get_attestation(const int fd,
    const uint8_t *user_data, const uint32_t user_data_len,
    const uint8_t *nonce_data, const uint32_t nonce_data_len,
    const uint8_t *pubkey_data, const uint32_t pubkey_len,
    uint8_t *att_doc_data, uint32_t *att_doc_data_len);
```

QTSM 设备路径在 SDK 内部为：

```text
/dev/qtsm
```

SDK 常量边界来自 `enclave/qtsm/include/qtsm_lib_comm.h`：

```text
QTSM_PCR_MAX_LENGTH       = 64
QTSM_MAX_PCR_COUNT        = 32
QTSM_MODULE_ID_MAX_SIZE   = 128
QTSM_CERTIFICATE_MAX_SIZE = 4096
QTSM_CERTIFICATE_MAX_DEPTH= 4
QTSM_PUBLIC_KEY_MAX_SIZE  = 1024
QTSM_USER_DATA_MAX_SIZE   = 512
QTSM_NONCE_MAX_SIZE       = 512
QTSM_SIGNATURE_MAX_SIZE   = 128
```

QTSM lib 内部请求/响应 buffer：

```text
QTSM_REQUEST_MAX_SIZE  = 0x1000
QTSM_RESPONSE_MAX_SIZE = 0x6000
```

内核驱动响应上限为 `0x8000`。当前 `proof-of-observation` QingTian provider 为 attestation 输出分配 `64 KiB`，Node verifier 限制 `128 KiB`，均大于真实样本约 `4.9 KiB`，可以覆盖现有 QTSM 文档大小。

SDK Rust wrapper 中定义：

```text
VMADDR_CID_QINGTIAN_HOST = 3
```

官方 qproxy enclave 侧也默认 `--parent-cid 3`。因此当前 `POO_PARENT_CIDS` 默认包含 `3` 是合理的；保留多 CID 候选仍有价值，便于后续兼容不同 runtime 或诊断环境。

宿主机 Docker 容器内没有 `/dev/qtsm`，所以本地 Docker 运行 smoke 程序报 `qtsm_lib_init failed: -1` 是预期行为；只有在 enclave 内才应成功。

## attestation smoke 程序

目录：

```bash
mkdir -p ~/qt-attest-smoke
cd ~/qt-attest-smoke
```

`qtsm_attest_smoke.c`：

```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qtsm_lib.h"

#define ATT_DOC_BUF_SIZE (64 * 1024)

static void write_file(const char *path, const uint8_t *buf, uint32_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        perror("fopen");
        exit(1);
    }
    if (fwrite(buf, 1, len, f) != len) {
        perror("fwrite");
        exit(1);
    }
    fclose(f);
}

int main(int argc, char **argv) {
    const char *nonce = argc > 1 && argv[1][0] ? argv[1] : "poo-qingtian-nonce-001";
    const char *pubkey = argc > 2 && argv[2][0] ? argv[2] : "poo-public-key-placeholder";
    const char *user_data = argc > 3 && argv[3][0] ? argv[3] : "poo-qingtian-user-data-001";

    uint8_t *att_doc = malloc(ATT_DOC_BUF_SIZE);
    uint32_t att_doc_len = ATT_DOC_BUF_SIZE;
    if (!att_doc) {
        fprintf(stderr, "malloc att_doc failed\n");
        return 1;
    }

    int fd = qtsm_lib_init();
    if (fd < 0) {
        fprintf(stderr, "qtsm_lib_init failed: %d\n", fd);
        free(att_doc);
        return 1;
    }

    int ret = qtsm_get_attestation(
        fd,
        (const uint8_t *)user_data, strlen(user_data),
        (const uint8_t *)nonce, strlen(nonce),
        (const uint8_t *)pubkey, strlen(pubkey),
        att_doc, &att_doc_len
    );

    if (ret != 0) {
        fprintf(stderr, "qtsm_get_attestation failed: %d\n", ret);
        qtsm_lib_exit(fd);
        free(att_doc);
        return 1;
    }

    printf("qtsm_get_attestation ok\n");
    printf("nonce=%s\n", nonce);
    printf("pubkey=%s\n", pubkey);
    printf("user_data=%s\n", user_data);
    printf("attestation_doc_len=%u\n", att_doc_len);

    write_file("/tmp/qt-attestation.cose", att_doc, att_doc_len);
    printf("written=/tmp/qt-attestation.cose\n");

    qtsm_lib_exit(fd);
    free(att_doc);
    return 0;
}
```

注意：曾经使用 `CMD ["sh", "-c", "..."]` 时，在 QingTian runtime 内出现过启动后秒退。最终改为直接执行脚本：

```dockerfile
CMD ["/root/run_attest_smoke.sh"]
```

或：

```dockerfile
CMD ["/root/run_attest_vsock.sh"]
```

## debug attestation 样本

debug 版用于快速 console 验证：

```text
digest=SHA384
pcr0=251ce67fb37e9fc24a99a9c4da67fd8dc63d34bf5004cde8ea82db5d131c91a0a94f10574b60409e591dbb033d1495c0
pcr8=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
nonce=poo-qingtian-nonce-001
pubkey=poo-public-key-placeholder
user_data=poo-qingtian-user-data-001
attestation_doc_len=4939
launch_mode=debug
```

console 中取得的 debug base64 已本地验证可解码：

```text
b64 length: 6588
cose length: 4939
```

debug 样本只用于解析器开发，不应作为生产可信证明样本。

## non-debug / production attestation via vsock

准备 `nc-vsock`：

```bash
sudo yum install -y gcc make
cd ~/qt-attest-smoke
git clone https://github.com/stefanha/nc-vsock.git
cd nc-vsock
make
ls -l nc-vsock
```

`run_attest_vsock.sh`：

```bash
#!/bin/sh
set +e

echo "qt-attest-vsock booted"

NONCE="${QT_NONCE:-poo-qingtian-nonce-prod-001}"
PUBKEY="${QT_PUBKEY:-poo-public-key-placeholder}"
USER_DATA="${QT_USER_DATA:-poo-qingtian-user-data-prod-001}"
PARENT_CID="${PARENT_CID:-3}"
PARENT_PORT="${PARENT_PORT:-9999}"

/root/qtsm_attest_smoke "$NONCE" "$PUBKEY" "$USER_DATA"
rc=$?

{
  echo "qtsm_attest_exit=$rc"
  echo "nonce=$NONCE"
  echo "pubkey=$PUBKEY"
  echo "user_data=$USER_DATA"
  if [ -f /tmp/qt-attestation.cose ]; then
    echo "attestation_base64_begin"
    base64 -w0 /tmp/qt-attestation.cose
    echo
    echo "attestation_base64_end"
  else
    echo "no_attestation_file"
  fi
} | /root/nc-vsock "$PARENT_CID" "$PARENT_PORT"

while true; do
  sleep 3600
done
```

构建 vsock 版镜像和 EIF：

```bash
docker build --no-cache -f Dockerfile.attest-vsock -t qt-attest-vsock .
qt enclave make-img --docker-uri qt-attest-vsock --eif qt-attest-vsock.eif
```

有效输出：

```text
digest=SHA384
pcr0=be0555479ab87dd7c50800c4f1fca30cffb20e483771285a8ed7c2046708e1d0cc7dbf58429dd6a76c952b4e6b1ffe4b
pcr8=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

父虚机窗口 A 监听：

```bash
cd ~/qt-attest-smoke
./nc-vsock/nc-vsock -l 9999 | tee qt-attestation-prod.out
```

窗口 B 启动 normal enclave：

```bash
cd ~/qt-attest-smoke
qt enclave start --mem 1024 --cpus 2 --eif qt-attest-vsock.eif --cid 4
qt enclave query
```

收到输出：

```text
Connection from cid 4 port 3176673441...
qtsm_attest_exit=0
nonce=poo-qingtian-nonce-prod-001
pubkey=poo-public-key-placeholder
user_data=poo-qingtian-user-data-prod-001
attestation_base64_begin
...
attestation_base64_end
```

保存样本：

```bash
awk '/attestation_base64_begin/{flag=1; next} /attestation_base64_end/{flag=0} flag{print}' qt-attestation-prod.out | tr -d '\n\r ' > qt-attestation-prod.b64
base64 -d qt-attestation-prod.b64 > qt-attestation-prod.cose
wc -c qt-attestation-prod.cose
```

有效结果：

```text
qt-attestation-prod.cose size: 4942 bytes
launch_mode=production
```

`qt-attestation-prod.meta`：

```text
digest=SHA384
pcr0=be0555479ab87dd7c50800c4f1fca30cffb20e483771285a8ed7c2046708e1d0cc7dbf58429dd6a76c952b4e6b1ffe4b
pcr8=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
nonce=poo-qingtian-nonce-prod-001
pubkey=poo-public-key-placeholder
user_data=poo-qingtian-user-data-prod-001
launch_mode=production
```

云上 sha256：

```text
3490a8b9f298a2c58cb240dfb1eb7dafc9e9a61bb8532e0dfe3224070765bbc7  qt-attestation-prod.b64
09131035d3d5f8b99fdbd6a6458585e992cc3bb6cc6738f72dd145c5dc60bf0b  qt-attestation-prod.cose
36943ca2b8a2b98dc217f5aaa55a637cf8b85f4ac96234fb77c69dce3354f501  qt-attestation-prod.meta
```

本地从粘贴文本恢复验证：

```text
b64_len: 6592
cose_len: 4942
b64_sha256: 3490a8b9f298a2c58cb240dfb1eb7dafc9e9a61bb8532e0dfe3224070765bbc7
cose_sha256: 09131035d3d5f8b99fdbd6a6458585e992cc3bb6cc6738f72dd145c5dc60bf0b
```

最后停止 enclave：

```bash
qt enclave stop --enclave-id 0
qt enclave query
```

最终 query：

```text
[]
```

## PCR8 和发布策略

签名示例：

```bash
openssl ecparam -out private-key.pem -name secp384r1 -genkey
openssl req -new -key private-key.pem -out ssl.csr
openssl x509 -req -days 365 -in ssl.csr -signkey private-key.pem -out server.pem

qt enclave make-img \
  --docker-uri your-image \
  --eif your-image.eif \
  --private-key private-key.pem \
  --signing-certificate server.pem
```

私钥和证书必须匹配：

```bash
openssl x509 -in server.pem -pubkey -noout > cert.pub
openssl pkey -in private-key.pem -pubout > key.pub
diff cert.pub key.pub
```

`diff` 无输出才表示匹配。

不同中转站要得到一致 `PCR0/PCR8`，推荐直接部署项目方发布的同一个 signed EIF。不要把发布私钥分发给第三方中转站。

已验证的 official-signed fixture：

```text
EIF: qt-qtsm-fixture.official-signed.eif
launch_mode: normal
digest: SHA384
PCR0: 74d6c5fa10418d50e62c5e0422b868a5912d664c7721a9742e2ffdae3ec49c6a4030e3a1f73c37c5ccd297730a77ec89
PCR8: 5d130027a732cb97a378d0dd0563b7a1e43cb220699a2739870558753fb5620bb71e7c9053310aee01ec50c00f502e03
nonce_b64: oFZzAsbVdJowTthtuz7U7/bdnU58V163ytEbxVz9VZI=
public_key_spki_b64: MCowBQYDK2VwAyEA1JXf/Ijtcl5W+VsW5aByVdey3y5m7yFuR8vdrjFk2Mc=
attestation_sha256: ec62dc507e87c99c93306f1c83ce951e01a52618c4f0c73cd3cb5ffdd12a316a
```

该 fixture 的 QTSM payload 已确认包含 `module_id`、`timestamp`、`digest`、`pcrs`、`certificate`、`cabundle`、`user_data`、`nonce`、`public_key`。`cabundle` 是 4 个 DER 证书组成的 CBOR array，不是拼接 DER。

证书链指纹：

```text
root:     F23443B4EB52A70719DF49BDDA0E57BB25F1C04530885DBECDBDE241C8C4F581
region:   12534B0B6A231A49E055AA38E5951441756322CE105118C28BECD27F23F31E8E
grid:     C9DB9591D01EF3CCA577E580F278D79F620C19A67E927D9D4479920DDE1C5CB6
instance: DAB7817D80C6A5964D554D83E565D1E4AB33DEEFEFCBC44A1BE2146BA5C651C5
leaf:     70E42B079CBA602681944B2D5C784C2AD6340D5373F265E1AE3E9290CDE3BC49
```

签名校准结论：

- COSE protected header 为 ES384 / `-35`。
- 被签数据为标准 COSE `Sig_structure = ["Signature1", protected, h'', payload]`。
- 真实 QTSM 输出的 96 字节 ECDSA signature 需要将 `r`、`s` 两个 48 字节分量分别反转字节序后，再按 IEEE-P1363/DER 交给 OpenSSL/Node 验签。
- 当前 Node verifier 已按该规则通过 official-signed fixture 正例和 PCR8/public key/nonce/root mismatch 反例。

## 对 proof-of-observation 的改造依据

建议保持原业务证明协议主体不变，只抽象 TEE evidence provider：

- `nitro` provider：继续调用 AWS Nitro NSM。
- `qingtian` provider：调用 QTSM `qtsm_get_attestation`。

proof JSON 建议增加：

```json
{
  "profile": "nitro | qingtian"
}
```

字段名统一使用 `profile`：历史 Nitro proof 可以缺省该字段并按 `nitro` 处理，QingTian proof 必须显式携带 `"profile": "qingtian"`。

QingTian verifier 应校验：

1. attestation document 是 QingTian COSE/CBOR 格式。
2. COSE 签名有效。
3. 证书链能链到固定的 QingTian trust anchor。
4. `digest == SHA384`。
5. `pcrs[0] == expected_pcr0`。
6. `pcrs[8] == expected_pcr8`。
7. `nonce == proof.nonce`。
8. `pubkey == proof.public_key`。
9. `user_data` 在 v1 QingTian profile 中不进入安全绑定；只允许作为诊断字段或留空。
10. timestamp 在可接受窗口内。

当前代码状态：

- `verifier/evidence-qingtian.ts` 已接入真实 QTSM COSE verifier。
- `enclave/src/evidence_qingtian.rs` 已接入 `qtsm_lib_init()` / `qtsm_get_attestation()` FFI。
- `TEE_PROFILE=qingtian` 会选择 QingTian provider；默认 Nitro 行为保持不变。

如果后续要把 `user_data` 作为扩展绑定字段，必须先更新 profile 规范和测试向量，不能在实现中临时加入 trust path。

当前 production smoke 样本可以作为 verifier 开发 fixture，但正式业务 fixture 需要使用真实 `proof-of-observation` enclave 镜像和真实业务公钥重新采集。

## 真实业务绑定样本要求

当前 smoke 程序为了验证 QTSM 链路，传入的是 ASCII placeholder：

```text
nonce=poo-qingtian-nonce-prod-001
pubkey=poo-public-key-placeholder
```

正式接入 `proof-of-observation` 时不能沿用这个输入形态。业务 proof 的兼容语义要求：

- `nonce` 传给 `qtsm_get_attestation` 的必须是 proof 顶层 `nonce` base64 解码后的原始字节。
- `pubkey` 传给 `qtsm_get_attestation` 的必须是飞地内 Ed25519 public key 的 SPKI DER 字节。
- proof 顶层 `public_key` 仍然是同一份 SPKI DER 字节的 base64 编码。
- verifier 必须从 QingTian attestation payload 中提取 attested nonce 和 attested public key，并逐字节证明它们与 proof 顶层字段一致。

不要把以下三种数据混用：

- base64 文本形式的 `nonce`。
- raw Ed25519 public key。
- SPKI DER public key。

只有 SPKI DER public key 与当前 Nitro proof 的 `public_key` 语义一致。
