<?php 

namespace App\Http\Middleware;

use Closure;
use Auth0\SDK\JWTVerifier;

class Auth0Middleware
{
  public function handle($request, Closure $next)
  {
    if(!$request->hasHeader('Authorization')) {
      return response()->json('Authorization header not found', 401);
    }
    $token = $request->bearerToken();
    if($request->header('Authoriztion') == null || $token == null) {
      return response()->json('No token provided', 401);
    }
    $this->retrieveAndValidateToken($token);
    return $next($request);
  }
  public function retrieveAndValidateToken($token)
  {
    try {
      $verified = new JWTVerifier([
        'supported_algs' => ['RS256'],
        'valid_audienceS' => ['https://authorsapi.com'],
        'authorized_iss' => ['https://dannytebj.auth0.com']
      ]);
      $decoded = $verifier->verifyAndDecode($token);
    }
    catch(\Auth0\SDK\Exception\CoreException $e) {
      throw $e;
    }
  }
}
?>