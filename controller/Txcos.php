<?php


namespace app\service\controller;


use beacon\core\Config;
use beacon\core\Controller;
use beacon\core\Method;
use beacon\core\Request;

class Txcos extends Controller
{

    // 临时密钥计算样例
    private function _hex2bin($data)
    {
        $len = strlen($data);
        return pack("H" . $len, $data);
    }

    // obj 转 query string
    private function json2str($obj, $notEncode = false)
    {
        ksort($obj);
        $arr = array();
        if (!is_array($obj)) {
            throw new Exception($obj + " must be a array");
        }
        foreach ($obj as $key => $val) {
            array_push($arr, $key . '=' . ($notEncode ? $val : rawurlencode($val)));
        }
        return join('&', $arr);
    }

    // 计算临时密钥用的签名
    private function getSignature($opt, $key, $method, $config)
    {
        $formatString = $method . $config['domain'] . '/?' . $this->json2str($opt, 1);
        $sign = hash_hmac('sha1', $formatString, $key);
        $sign = base64_encode($this->_hex2bin($sign));
        return $sign;
    }

    // v2接口的key首字母小写，v3改成大写，此处做了向下兼容
    private function backwardCompat($result)
    {
        if (!is_array($result)) {
            throw new Exception($result + " must be a array");
        }
        $compat = array();
        foreach ($result as $key => $value) {
            if (is_array($value)) {
                $compat[lcfirst($key)] = $this->backwardCompat($value);
            } elseif ($key == 'Token') {
                $compat['sessionToken'] = $value;
            } else {
                $compat[lcfirst($key)] = $value;
            }
        }
        return $compat;
    }

    // 获取临时密钥
    private function getTempKeys($config)
    {
        if (array_key_exists('bucket', $config)) {
            $ShortBucketName = substr($config['bucket'], 0, strripos($config['bucket'], '-'));
            $AppId = substr($config['bucket'], 1 + strripos($config['bucket'], '-'));
        }
        if (array_key_exists('policy', $config)) {
            $policy = $config['policy'];
        } else {
            $policy = array(
                'version' => '2.0',
                'statement' => array(
                    array(
                        'action' => $config['allowActions'],
                        'effect' => 'allow',
                        'principal' => array('qcs' => array('*')),
                        'resource' => array(
                            'qcs::cos:' . $config['region'] . ':uid/' . $AppId . ':prefix//' . $AppId . '/' . $ShortBucketName . '/' . $config['allowPrefix']
                        )
                    )
                )
            );
        }
        $policyStr = str_replace('\\/', '/', json_encode($policy));
        $Action = 'GetFederationToken';
        $Nonce = rand(10000, 20000);
        $Timestamp = time();
        $Method = 'POST';
        $params = array(
            'SecretId' => $config['secretId'],
            'Timestamp' => $Timestamp,
            'Nonce' => $Nonce,
            'Action' => $Action,
            'DurationSeconds' => $config['durationSeconds'],
            'Version' => '2018-08-13',
            'Name' => 'cos',
            'Region' => 'ap-guangzhou',
            'Policy' => urlencode($policyStr)
        );
        $params['Signature'] = $this->getSignature($params, $config['secretKey'], $Method, $config);
        $url = $config['url'];
        $ch = curl_init($url);
        if (array_key_exists('proxy', $config)) {
            $config['proxy'] && curl_setopt($ch, CURLOPT_PROXY, $config['proxy']);
        }
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $this->json2str($params));
        $result = curl_exec($ch);
        if (curl_errno($ch)) $result = curl_error($ch);
        curl_close($ch);
        $result = json_decode($result, 1);
        if (isset($result['Response'])) {
            $result = $result['Response'];
            $result['startTime'] = $result['ExpiredTime'] - $config['durationSeconds'];
        }
        $result = $this->backwardCompat($result);
        return $result;
    }

    private function getAuthorization($keys, $method, $pathname): string
    {
        // 获取个人 API 密钥 https://console.qcloud.com/capi
        $SecretId = $keys['credentials']['tmpSecretId'];
        $SecretKey = $keys['credentials']['tmpSecretKey'];

        // 整理参数
        $query = [];
        $headers = [];
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
            $list = [];
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
        $now = time();
        $expired = $now + 600; // 签名过期时刻，600 秒后
        // 要用到的 Authorization 参数列表
        $qSignAlgorithm = 'sha1';
        $qAk = $SecretId;
        $qKeyTime = $now . ';' . $expired;
        $qHeaderList = strtolower(implode(';', getObjectKeys($headers)));
        $qUrlParamList = strtolower(implode(';', getObjectKeys($query)));
        // 签名算法说明文档：https://www.qcloud.com/document/product/436/7778
        // 步骤一：计算 SignKey
        $signKey = hash_hmac("sha1", $qKeyTime, $SecretKey);
        // 步骤二：构成 FormatString
        $formatString = implode("\n", [strtolower($method), $pathname, obj2str($query), obj2str($headers), '']);
        // 步骤三：计算 StringToSign
        $stringToSign = implode("\n", ['sha1', $qKeyTime, sha1($formatString), '']);
        // 步骤四：计算 Signature
        $qSignature = hash_hmac('sha1', $stringToSign, $signKey);
        // 步骤五：构造 Authorization
        return implode('&', [
            'q-sign-algorithm=' . $qSignAlgorithm,
            'q-ak=' . $qAk,
            'q-sign-time=' . $qKeyTime,
            'q-key-time=' . $qKeyTime,
            'q-header-list=' . $qHeaderList,
            'q-url-param-list=' . $qUrlParamList,
            'q-signature=' . $qSignature
        ]);
    }

    #[Method(act: 'auth', method: Method::GET | Method::POST, contentType: 'json')]
    public function auth(string $method = 'post', string $pathname = '/')
    {
        // 配置参数
        $config = array(
            'url' => 'https://sts.tencentcloudapi.com/',
            'domain' => 'sts.tencentcloudapi.com',
            'proxy' => '',
            'secretId' => 'AKIDZBW2FHA7rnTN7elKablfmbATZS5Vovvh', // 固定密钥
            'secretKey' => 'e4A0f6ex1qc2LGvnQmsjKguyvc3FAtNg', // 固定密钥
            'bucket' => 'bz-test-1251004022', // 换成你的 bucket
            'region' => 'ap-guangzhou', // 换成 bucket 所在园区
            'durationSeconds' => 1800, // 密钥有效期
            // 允许操作（上传）的对象前缀，可以根据自己网站的用户登录态判断允许上传的目录，例子： user1/* 或者 * 或者a.jpg
            // 请注意当使用 * 时，可能存在安全风险，详情请参阅：https://cloud.tencent.com/document/product/436/40265
            'allowPrefix' => '_ALLOW_DIR_/*',
            // 密钥的权限列表。简单上传和分片需要以下的权限，其他权限列表请看 https://cloud.tencent.com/document/product/436/31923
            'allowActions' => [
                // 所有 action 请看文档 https://cloud.tencent.com/document/product/436/31923
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
            ]
        );
        // 获取临时密钥，计算签名
        $tempKeys = $this->getTempKeys($config);
        if ($tempKeys && isset($tempKeys['credentials'])) {
            $data = [
                'Authorization' => $this->getAuthorization($tempKeys, $method, $pathname),
                'XCosSecurityToken' => $tempKeys['credentials']['sessionToken'],
            ];
        } else {
            $data = ['error' => $tempKeys];
        }
        // 返回数据给前端
        header('Content-Type: application/json');
        header('Access-Control-Allow-Origin: *'); // 这里修改允许跨域访问的网站
        header('Access-Control-Allow-Headers: origin,accept,content-type');
        echo json_encode($data);
    }


}