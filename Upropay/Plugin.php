<?php

namespace Plugin\Upropay;

use App\Services\Plugin\AbstractPlugin;
use App\Contracts\PaymentInterface;
use Illuminate\Support\Facades\Log;

class Plugin extends AbstractPlugin implements PaymentInterface
{
    public function boot(): void
    {
        $this->filter('available_payment_methods', function ($methods) {
            if ($this->getConfig('enabled', true)) {
                $methods['Upropay'] = [
                    'name' => $this->getConfig('display_name', 'Upropay'),
                    'icon' => $this->getConfig('icon', '💳'),
                    'plugin_code' => $this->getPluginCode(),
                    'type' => 'plugin'
                ];
            }
            return $methods;
        });
    }

    public function form(): array
    {
        return [
            'api_url' => [
                'label' => 'API URL',
                'description' => 'Upropay API 地址',
                'type' => 'string',
            ],
            'api_key' => [
                'label' => 'API Key',
                'description' => '您的 API Key (X-API-KEY)',
                'type' => 'string',
            ],
            'webhook_secret' => [
                'label' => 'Webhook Secret',
                'description' => '用于验证签名的 Secret',
                'type' => 'string',
            ],
            'chain' => [
                'label' => '链',
                'description' => '区块链网络 (TRON 或 BSC)',
                'type' => 'string',
                'default' => 'TRON',
            ],
            'order_prefix' => [
                'label' => '订单号前缀',
                'description' => '例如: Upropay_',
                'type' => 'string',
            ],
            'return_url' => [
                'label' => '支付成功后的跳转地址',
                'description' => 'https://upropay.vip',
                'type' => 'string',
            ],
            'wallet_tag' => [
                'label' => '钱包标签',
                'description' => '用于选择特定收款钱包的标签 (可选)',
                'type' => 'string',
            ]
        ];
    }

    public function pay($order): array
    {
        if (!filter_var($this->config['api_url'], FILTER_VALIDATE_URL)) {
            \abort(500, 'UproPay: API URL 非法');
        }

        $merchantOrderId = ($this->config['order_prefix'] ?? '') . $order['trade_no'];

        // ✅ 金额修复（避免 float 精度问题）
        $amount = number_format($order['total_amount'] / 100, 2, '.', '');

        // ✅ chain 标准化
        $chain = strtoupper($this->config['chain'] ?? 'TRON');
        if (!in_array($chain, ['TRON', 'BSC'])) {
            $chain = 'TRON';
        }

        $payload = [
            'merchantOrderId' => $merchantOrderId,
            'amount' => $amount,
            'chain' => $chain,
            'notifyUrl' => $order['notify_url'],
            'redirectUrl' => !empty($this->config['return_url']) ? $this->config['return_url'] : $order['return_url']
        ];

        if (!empty($this->config['wallet_tag'])) {
            $payload['walletTag'] = $this->config['wallet_tag'];
        }

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, rtrim($this->config['api_url'], '/') . '/api/transactions');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'X-API-KEY: ' . $this->config['api_key'],
            'Content-Type: application/json',
            'Accept: application/json'
        ]);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($response === false) {
            \abort(500, 'UproPay: 网络请求失败 - ' . $error);
        }

        $result = json_decode($response, true);

        if ($httpCode >= 400) {
            $serverMsg = $result['message'] ?? '未知错误';
            if (is_array($serverMsg)) {
                $serverMsg = json_encode($serverMsg, JSON_UNESCAPED_UNICODE);
            }
            if ($httpCode === 403) {
                \abort(500, '域名未授权: ' . $serverMsg);
            }
            if ($httpCode === 404) {
                if (strpos((string)$serverMsg, 'No active wallet found') !== false) {
                    \abort(500, '收款地址不存在: ' . $serverMsg);
                }
                \abort(500, '接口 404: ' . $serverMsg);
            }
            \abort(500, "UproPay: 接口返回({$httpCode}): " . $serverMsg);
        }

        if (!isset($result['paymentUrl'])) {
            \abort(500, 'UproPay: 接口响应异常');
        }

        $paymentUrl = $result['paymentUrl'];
        $returnUrl = !empty($this->config['return_url']) ? $this->config['return_url'] : $order['return_url'];

        // ✅ 防重复拼接 redirectUrl
        if ($returnUrl && strpos($paymentUrl, 'redirectUrl=') === false) {
            $paymentUrl .= (strpos($paymentUrl, '?') === false ? '?' : '&') . 'redirectUrl=' . urlencode($returnUrl);
        }

        return [
            'type' => 1,
            'data' => $paymentUrl
        ];
    }

    public function notify($params): array|bool
    {
        $signature = \request()->header('X-Signature') ?? ($params['signature'] ?? null);
        if (!$signature) {
            return false;
        }

        $payload = $params;
        if (isset($payload['signature'])) {
            unset($payload['signature']);
        }

        // ✅ JSON 签名验证
        $jsonPayload = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $expected = hash_hmac('sha256', $jsonPayload, $this->config['webhook_secret']);

        if (!hash_equals($expected, $signature)) {
            // fallback: raw body
            $rawPayload = \request()->getContent();
            $expectedRaw = hash_hmac('sha256', $rawPayload, $this->config['webhook_secret']);

            if (!hash_equals($expectedRaw, $signature)) {
                Log::error('UproPay notify signature verify failed', [
                    'signature' => $signature,
                    'expected_json' => $expected,
                    'expected_raw' => $expectedRaw,
                    'params' => $params
                ]);
                return false;
            }
        }

        // ✅ 状态校验
        if (strtoupper($params['status']) !== 'CONFIRMED') {
            return false;
        }

        // 订单号处理
        $tradeNo = $params['merchantOrderId'];
        if (!empty($this->config['order_prefix'])) {
            if (strpos($tradeNo, $this->config['order_prefix']) === 0) {
                $tradeNo = substr($tradeNo, strlen($this->config['order_prefix']));
            }
        }

        // ✅ 金额校验（核心安全）
        if (!isset($params['amount'])) {
            return false;
        }

        $callbackAmount = number_format((float)$params['amount'], 2, '.', '');

        $order = \App\Models\Order::where('trade_no', $tradeNo)->first();
        if (!$order) {
            return false;
        }

        $orderAmount = number_format($order->total_amount / 100, 2, '.', '');

        if ($callbackAmount !== $orderAmount) {
            Log::error('UproPay amount mismatch', [
                'trade_no' => $tradeNo,
                'callback_amount' => $callbackAmount,
                'order_amount' => $orderAmount
            ]);
            return false;
        }

        // ✅ 成功日志（建议保留）
        Log::info('UproPay notify success', [
            'trade_no' => $tradeNo,
            'amount' => $callbackAmount
        ]);

        return [
            'trade_no' => $tradeNo,
            'callback_no' => $params['id']
        ];
    }
}