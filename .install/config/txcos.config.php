<?php

return [
    //网盘数据信息----------------------------------------
    'domain' => 'sts.api.qcloud.com',
    'sign_url' => 'https://sts.api.qcloud.com/v2/index.php',
    'proxy' => '',
    'secret_id' => '', // 固定密钥
    'secret_key' => '', // 固定密钥
    'bucket' => 'wj008-1252002938',
    'region' => 'ap-beijing',
    'allow_prefix' => ['upfiles/*', 'video/*'], // 必填，这里改成允许的路径前缀，这里可以根据自己网站的用户登录态判断允许上传的目录，例子：* 或者 a/* 或者 a.jpg
    //上传图片路径
    'upload_url' => 'https://wj008-1252002938.cos.ap-beijing.myqcloud.com',
    'web_url' => 'https://wj008-1252002938.cos.ap-beijing.myqcloud.com',
];

