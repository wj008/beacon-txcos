<?php


namespace app\service\controller;


use beacon\core\Config;
use beacon\core\Controller;
use beacon\core\Method;
use beacon\core\Request;

class Txcos extends Controller
{
    /**
     * 参数转换
     * @param $obj
     * @return string
     */
    private static function toParam($obj): string
    {
        ksort($obj);
        $arr = array();
        foreach ($obj as $key => $val) {
            array_push($arr, $key . '=' . $val);
        }
        return join('&', $arr);
    }

    /**
     * 获取签名
     * @param $opt
     * @param $key
     * @param $method
     * @return string
     */
    private static function getSignature($opt, $key, $method): string
    {
        $domain = Config::get('txcos.domain', '');
        $formatString = $method . $domain . '/v2/index.php?' . self::toParam($opt);
        $sign = hash_hmac('sha1', $formatString, $key);
        return base64_encode(hex2bin($sign));
    }

    /**
     * 获得临时钥匙
     * @return array
     */
    private static function getTempKeys(): array
    {
        $bucket = Config::get('txcos.bucket', '');
        $allowPrefix = Config::get('txcos.allow_prefix', '_ALLOW_DIR_/*');
        $region = Config::get('txcos.region');
        $secretId = Config::get('txcos.secret_id');
        $secretKey = Config::get('txcos.secret_key');
        $proxy = Config::get('txcos.proxy');
        $signUrl = Config::get('txcos.sign_url');

        // 判断是否修改了 AllowPrefix
        if ($allowPrefix === '_ALLOW_DIR_/*') {
            return array('error' => '请修改 AllowPrefix 配置项，指定允许上传的路径前缀');
        }
        $ShortBucketName = substr($bucket, 0, strripos($bucket, '-'));
        $AppId = substr($bucket, 1 + strripos($bucket, '-'));
        $resource = [];
        $resource[] = 'qcs::cos:' . $region . ':uid/' . $AppId . ':prefix//' . $AppId . '/' . $ShortBucketName . '/';
        if (is_array($allowPrefix)) {
            foreach ($allowPrefix as $prefix) {
                $resource[] = 'qcs::cos:' . $region . ':uid/' . $AppId . ':prefix//' . $AppId . '/' . $ShortBucketName . '/' . $prefix;
            }
        } else {
            $resource[] = 'qcs::cos:' . $region . ':uid/' . $AppId . ':prefix//' . $AppId . '/' . $ShortBucketName . '/' . $allowPrefix;
        }
        $policy = array(
            'version' => '2.0',
            'statement' => array(
                array(
                    'action' => array(
                        // // 这里可以从临时密钥的权限上控制前端允许的操作
                        //  'name/cos:*', // 这样写可以包含下面所有权限
                        // // 列出所有允许的操作
                        // // ACL 读写
                        // 'name/cos:GetBucketACL',
                        // 'name/cos:PutBucketACL',
                        // 'name/cos:GetObjectACL',
                        // 'name/cos:PutObjectACL',
                        // // 简单 Bucket 操作
                        // 'name/cos:PutBucket',
                        // 'name/cos:HeadBucket',
                        // 'name/cos:GetBucket',
                        // 'name/cos:DeleteBucket',
                        // 'name/cos:GetBucketLocation',
                        // // Versioning
                        // 'name/cos:PutBucketVersioning',
                        // 'name/cos:GetBucketVersioning',
                        // // CORS
                        // 'name/cos:PutBucketCORS',
                        // 'name/cos:GetBucketCORS',
                        // 'name/cos:DeleteBucketCORS',
                        // // Lifecycle
                        // 'name/cos:PutBucketLifecycle',
                        // 'name/cos:GetBucketLifecycle',
                        // 'name/cos:DeleteBucketLifecycle',
                        // // Replication
                        // 'name/cos:PutBucketReplication',
                        // 'name/cos:GetBucketReplication',
                        // 'name/cos:DeleteBucketReplication',
                        // // 删除文件
                        // 'name/cos:DeleteMultipleObject',
                        // 'name/cos:DeleteObject',
                        // 简单文件操作
                        'name/cos:PutObject',
                        'name/cos:PostObject',
                        'name/cos:AppendObject',
                        'name/cos:GetObject',
                        'name/cos:HeadObject',
                        'name/cos:OptionsObject',
                        'name/cos:PutObjectCopy',
                        'name/cos:PostObjectRestore',
                        // 分片上传操作
                        'name/cos:InitiateMultipartUpload',
                        'name/cos:ListMultipartUploads',
                        'name/cos:ListParts',
                        'name/cos:UploadPart',
                        'name/cos:CompleteMultipartUpload',
                        'name/cos:AbortMultipartUpload',
                    ),
                    'effect' => 'allow',
                    'principal' => array('qcs' => array('*')),
                    'resource' => $resource
                )
            )
        );
        $policyStr = str_replace('\\/', '/', json_encode($policy));

        // 有效时间小于 30 秒就重新获取临时密钥，否则使用缓存的临时密钥
        $tempKeysCache = Request::getSession('tempKeysCache', null);
        if (!empty($tempKeysCache)) {
            if (isset($tempKeysCache['expiredTime']) && isset($tempKeysCache['policyStr']) && $tempKeysCache['expiredTime'] - time() > 30 && $tempKeysCache['policyStr'] === $policyStr) {
                return $tempKeysCache;
            }
        }
        $Action = 'GetFederationToken';
        $Nonce = rand(10000, 20000);
        $Timestamp = time() - 1;
        $Method = 'GET';
        $params = array(
            'Action' => $Action,
            'Nonce' => $Nonce,
            'Region' => '',
            'SecretId' => $secretId,
            'Timestamp' => $Timestamp,
            'durationSeconds' => 7200,
            'name' => '',
            'policy' => $policyStr
        );
        $params['Signature'] = urlencode(self::getSignature($params, $secretKey, $Method));
        $url = $signUrl . '?' . self::toParam($params);

        $ch = curl_init($url);
        if (!empty($proxy)) {
            curl_setopt($ch, CURLOPT_PROXY, $proxy);
        }
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $result = curl_exec($ch);
        if (curl_errno($ch)) $result = curl_error($ch);
        curl_close($ch);
        $result = json_decode($result, 1);
        if (isset($result['data'])) {
            $result = $result['data'];
        }
        $tempKeysCache = $result;
        $tempKeysCache['policyStr'] = $policyStr;
        Request::setSession('tempKeysCache', $tempKeysCache);
        return $result;
    }

    // 计算 COS API 请求用的签名
    private static function getAuthorization($keys, $method, $pathname): string
    {
        // 获取个人 API 密钥 https://console.qcloud.com/capi
        $SecretId = $keys['credentials']['tmpSecretId'];
        $SecretKey = $keys['credentials']['tmpSecretKey'];
        // 整理参数
        $query = array();
        $headers = array();
        $method = strtolower($method ? $method : 'get');
        $pathname = $pathname ? $pathname : '/';
        substr($pathname, 0, 1) != '/' && ($pathname = '/' . $pathname);
        // 工具方法
        function getObjectKeys($obj)
        {
            $list = array_keys($obj);
            sort($list);
            return $list;
        }

        function obj2str($obj)
        {
            $list = array();
            $keyList = getObjectKeys($obj);
            $len = count($keyList);
            for ($i = 0; $i < $len; $i++) {
                $key = $keyList[$i];
                $val = $obj[$key] ?? '';
                $key = strtolower($key);
                $list[] = rawurlencode($key) . '=' . rawurlencode($val);
            }
            return implode('&', $list);
        }

        // 签名有效起止时间
        $now = time() - 1;
        $expired = $now + 600; // 签名过期时刻，600 秒后
        // 要用到的 Authorization 参数列表
        $qSignAlgorithm = 'sha1';
        $qAk = $SecretId;
        $qSignTime = $now . ';' . $expired;
        $qKeyTime = $now . ';' . $expired;
        $qHeaderList = strtolower(implode(';', getObjectKeys($headers)));
        $qUrlParamList = strtolower(implode(';', getObjectKeys($query)));
        // 签名算法说明文档：https://www.qcloud.com/document/product/436/7778
        // 步骤一：计算 SignKey
        $signKey = hash_hmac("sha1", $qKeyTime, $SecretKey);
        // 步骤二：构成 FormatString
        $formatString = implode("\n", array(strtolower($method), $pathname, obj2str($query), obj2str($headers), ''));
        //header('x-test-method', $method);
        //header('x-test-pathname', $pathname);
        // 步骤三：计算 StringToSign
        $stringToSign = implode("\n", array('sha1', $qSignTime, sha1($formatString), ''));
        // 步骤四：计算 Signature
        $qSignature = hash_hmac('sha1', $stringToSign, $signKey);
        // 步骤五：构造 Authorization
        $authorization = implode('&', array(
            'q-sign-algorithm=' . $qSignAlgorithm,
            'q-ak=' . $qAk,
            'q-sign-time=' . $qSignTime,
            'q-key-time=' . $qKeyTime,
            'q-header-list=' . $qHeaderList,
            'q-url-param-list=' . $qUrlParamList,
            'q-signature=' . $qSignature
        ));
        return $authorization;
    }

    #[Method(act: 'auth', method: Method::GET | Method::POST, contentType: 'json')]
    public function auth(string $method = 'get', string $pathname = '/')
    {
        // 获取临时密钥，计算签名
        $tempKeys = self::getTempKeys();
        if ($tempKeys && isset($tempKeys['credentials'])) {
            $data = array(
                'Authorization' => self::getAuthorization($tempKeys, $method, $pathname),
                'XCosSecurityToken' => $tempKeys['credentials']['sessionToken'],
            );
        } else {
            $data = array('error' => $tempKeys);
        }
        // 返回数据给前端
        //header('Content-Type: application/json');
        header('Access-Control-Allow-Origin: *'); // 这里修改允许跨域访问的网站
        header('Access-Control-Allow-Headers: origin,accept,content-type');
        return $data;
    }


}