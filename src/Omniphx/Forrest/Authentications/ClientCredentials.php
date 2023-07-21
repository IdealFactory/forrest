<?php

namespace Omniphx\Forrest\Authentications;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Omniphx\Forrest\Client as BaseAuthentication;
use Omniphx\Forrest\Interfaces\AuthenticationInterface;

class ClientCredentials extends BaseAuthentication implements AuthenticationInterface
{
    public function authenticate($url = null)
    {
        $domain = $url ?? $this->credentials['loginURL'] . '/services/oauth2/token';

        // Generate the form parameters
        $parameters = [
            'grant_type' => 'client_credentials',
            'client_id'     => $this->credentials['consumerKey'],
            'client_secret' => $this->credentials['consumerSecret'],
        ];

        // \Psr\Http\Message\ResponseInterface
        $response = $this->httpClient->request('post', $domain, ['form_params' => $parameters]);

        $authToken = json_decode($response->getBody()->getContents(), true);

        $this->handleAuthenticationErrors($authToken);

        $this->tokenRepo->put($authToken);

        $this->storeVersion();
        $this->storeResources();
        return $authToken;
    }

    /**
     * @return void
     */
    public function refresh()
    {
        return $this->authenticate();
    }

    /**
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function revoke()
    {
        $accessToken = $this->tokenRepo->get()['access_token'];
        $url = $this->credentials['loginURL'].'/services/oauth2/revoke';

        $options['headers']['content-type'] = 'application/x-www-form-urlencoded';
        $options['form_params']['token'] = $accessToken;

        return $this->httpClient->request('post', $url, $options);
    }
}
