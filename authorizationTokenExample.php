<?php 
 //request to get a token Oauth2.0
    public function tokenAuth()
    {
        $url = 'https://idp.comprobanteselectronicos.go.cr/auth/realms/rut-stag/protocol/openid-connect/token';//access token url
        $data = array('client_id' => 'api-stag',//Test: 'api-stag' Production: 'api-prod'
                      'client_secret' => '',//always empty
                      'grant_type' => 'password', //always 'password'
                      //go to https://www.hacienda.go.cr/ATV/login.aspx to generate a username and password credentials
                      'username' => 'ATV user', 
                      'password' => 'ATV pass', 
                      'scope' =>'');//always empty
        // use key 'http' even if you send the request to https://...
        $options = array(
            'http' => array(
                'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
                'method'  => 'POST',
                'content' => http_build_query($data)
            )
        );
        $context  = stream_context_create($options);
        $result = file_get_contents($url, false, $context);
        if ($result === FALSE) { echo $result; }
        $token = json_decode($result); //get a token object
        return $token; //return a json object whith token and refresh token
    }
