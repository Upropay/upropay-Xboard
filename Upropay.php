<?php

namespace App\Payments;

use GuzzleHttp\Client;

class UproPay {
    private $config;

    public function __construct($config)
    {
        $this->config = $config;
    }

    public function form()
    {
        return [
            'api_url' => [
                'label' => 'API URL',
                'description' => '例如: https://upropay.vip',
                'type' => 'input',
            ],
            'api_key' => [
                'label' => 'API Key',
                'description' => '您的 API Key (X-API-KEY)',
                'type' => 'input',
            ],
            'webhook_secret' => [
                'label' => 'Webhook Secret',
                'description' => '用于验证签名的 Secret',
                'type' => 'input',
            ],
            'chain' => [
                'label' => 'Chain',
                'description' => '区块链网络 (TRON 或 BSC)',
                'type' => 'input',
            ],
            'order_prefix' => [
                'label' => '订单号前缀',
                'description' => '例如: v2board_',
                'type' => 'input',
            ],
            'return_url' => [
                'label' => '支付成功后的跳转地址',
                'description' => '例如: https://your-site.com/#/order',
                'type' => 'input',
            ],
            'wallet_tag' => [
                'label' => 'Wallet Tag',
                'description' => '用于选择特定收款钱包的标签 (可选)',
                'type' => 'input',
            ]
        ];
    }

    public function pay($order)
    {
        $client = new Client([
            'base_uri' => $this->config['api_url'],
            'timeout'  => 10.0,
        ]);

        $merchantOrderId = ($this->config['order_prefix'] ?? '') . $order['trade_no'];

        $payload = [
            'merchantOrderId' => $merchantOrderId,
            'amount' => (float)($order['total_amount'] / 100),
            'chain' => $this->config['chain'] ?? 'TRON',
            'notifyUrl' => $order['notify_url'],
            'redirectUrl' => !empty($this->config['return_url']) ? $this->config['return_url'] : $order['return_url']
        ];

        if (!empty($this->config['wallet_tag'])) {
            $payload['walletTag'] = $this->config['wallet_tag'];
        }

        try {
            $response = $client->post('/api/transactions', [
                'headers' => [
                    'X-API-KEY' => $this->config['api_key'],
                    'Content-Type' => 'application/json',
                    'Accept' => 'application/json'
                ],
                'json' => $payload
            ]);

            $result = json_decode($response->getBody()->getContents(), true);

            if (!isset($result['paymentUrl'])) {
                abort(500, 'UproPay: 接口响应异常');
            }

            $paymentUrl = $result['paymentUrl'];
            $returnUrl = !empty($this->config['return_url']) ? $this->config['return_url'] : $order['return_url'];
            if ($returnUrl) {
                $paymentUrl .= (strpos($paymentUrl, '?') === false ? '?' : '&') . 'redirectUrl=' . urlencode($returnUrl);
            }

            return [
                'type' => 1, // 0:qrcode 1:url
                'data' => $paymentUrl
            ];
        } catch (\Exception $e) {
            $message = $e->getMessage();
            if ($e instanceof \GuzzleHttp\Exception\ClientException) {
                $response = $e->getResponse();
                if ($response) {
                    $body = json_decode($response->getBody()->getContents(), true);
                    $serverMsg = isset($body['message']) ? $body['message'] : '未知错误';
                    if ($response->getStatusCode() === 403) {
                        abort(500, '域名未授权: ' . $serverMsg);
                    }
                    if ($response->getStatusCode() === 404) {
                        if (strpos($serverMsg, 'No active wallet found') !== false) {
                            abort(500, '收款地址不存在: ' . $serverMsg);
                        }
                        abort(500, '接口 404: ' . $serverMsg);
                    }
                    $message = "接口返回({$response->getStatusCode()}): " . $serverMsg;
                }
            }
            abort(500, 'UproPay: ' . $message);
        }
    }

    public function notify($params)
    {
        $signature = request()->header('X-Signature') ?? ($params['signature'] ?? null);
        if (!$signature) {
            return false;
        }

        $payload = $params;
        if (isset($payload['signature'])) {
            unset($payload['signature']);
        }

        // Try to verify using the parsed array (common for Node.js/JSON APIs)
        $jsonPayload = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $expected = hash_hmac('sha256', $jsonPayload, $this->config['webhook_secret']);

        if ($signature !== $expected) {
            // Try raw body if signature is from header (just in case the server signed the whole raw body)
            $rawPayload = request()->getContent();
            $expectedRaw = hash_hmac('sha256', $rawPayload, $this->config['webhook_secret']);
            if ($signature !== $expectedRaw) {
                \Illuminate\Support\Facades\Log::error('UproPay notify signature verify failed', [
                    'signature' => $signature,
                    'expected_json' => $expected,
                    'expected_raw' => $expectedRaw,
                    'json_payload' => $jsonPayload,
                    'params' => $params
                ]);
                return false;
            }
        }

        if (strtoupper($params['status']) !== 'CONFIRMED') {
            return false;
        }

        $tradeNo = $params['merchantOrderId'];
        if (!empty($this->config['order_prefix'])) {
            if (strpos($tradeNo, $this->config['order_prefix']) === 0) {
                $tradeNo = substr($tradeNo, strlen($this->config['order_prefix']));
            }
        }

        return [
            'trade_no' => $tradeNo,
            'callback_no' => $params['id']
        ];
    }
}
