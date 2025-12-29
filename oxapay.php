<?php

namespace Paymenter\Extensions\Gateways\oxapay;

use App\Attributes\ExtensionMeta;
use App\Classes\Extension\Gateway;
use App\Helpers\ExtensionHelper;
use App\Models\Invoice;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class oxapay extends Gateway
{
    public function boot()
    {
        require __DIR__ . '/routes.php';
    }

    private function request(string $url, string $method = 'get', array $data = [])
    {
        $response = Http::withHeaders([
            'Authorization' => 'Bearer ' . $this->config('api_key'),
            'Content-Type'  => 'application/json',
        ])->$method('https://api.oxapay.com' . $url, $data);

        if (!$response->successful()) {
            $error = $response->json('detail') ?? $response->body();
            throw new Exception('OxaPay API error: ' . $error);
        }

        return $response->json();
    }

    public function getConfig($values = [])
    {
        return [
            [
                'name'     => 'api_key',
                'label'    => 'API Key',
                'type'     => 'text',
                'required' => true,
            ],
            [
                'name'     => 'webhook_secret',
                'label'    => 'Webhook Secret',
                'type'     => 'text',
                'required' => true,
            ],
        ];
    }

    public function pay(Invoice $invoice, $total)
    {
        $response = $this->request('/v2/payments', 'post', [
            'amount' => [
                'currency' => $invoice->currency_code,
                'value'    => number_format($total, 2, '.', ''),
            ],
            'description' => 'Invoice #' . $invoice->id,
            'redirectUrl' => route('invoices.show', $invoice) . '?checkPayment=true',
            'webhookUrl'  => route('extensions.gateways.oxapay.webhook'),
            'metadata'    => [
                'invoice_id' => $invoice->id,
            ],
        ]);

        return $response['_links']['checkout']['href'];
    }

    public function webhook(Request $request)
    {
        $rawBody   = $request->getContent();
        $signature = $request->header('X-OxaPay-Signature');

        if (!$signature) {
            abort(400, 'Missing signature');
        }

        $expected = hash_hmac('sha256', $rawBody, $this->config('webhook_secret'));

        if (!hash_equals($expected, $signature)) {
            abort(403, 'Invalid signature');
        }

        $payload = json_decode($rawBody, true);

        if (
            empty($payload['id']) ||
            empty($payload['status']) ||
            empty($payload['metadata']['invoice_id'])
        ) {
            abort(400, 'Invalid payload');
        }

        if ($payload['status'] !== 'paid') {
            return response()->json(['ignored' => true]);
        }

        $invoiceId     = (int) $payload['metadata']['invoice_id'];
        $transactionId = (string) $payload['id'];
        $amount        = (float) $payload['amount']['value'];

        // Idempotency protection
        if (ExtensionHelper::paymentExists($transactionId)) {
            return response()->json(['duplicate' => true]);
        }

        ExtensionHelper::addPayment(
            $invoiceId,
            'oxapay',
            $amount,
            transactionId: $transactionId
        );

        return response()->json(['success' => true]);
    }
}
