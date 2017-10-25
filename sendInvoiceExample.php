<?php 
//send invoice xml to Hacienda API
    public function send_invoice() {
        $consecutive = $this->generate_consecutive(); //consecutive invoice number
        $key = $this->generate_key($consecutive); //key invoice number
        $invoice = $this->set_invoice($consecutive,$key);//create a xml string
        $authToken = $this->get_token();//get OAuth2.0 token

        $curl = curl_init();

        curl_setopt_array($curl, array(
          CURLOPT_URL => "https://api.comprobanteselectronicos.go.cr/recepcion-sandbox/v1/recepcion",
          CURLOPT_RETURNTRANSFER => true,
          CURLOPT_ENCODING => "",
          CURLOPT_MAXREDIRS => 10,
          CURLOPT_TIMEOUT => 30,
          CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
          CURLOPT_CUSTOMREQUEST => "POST",
          CURLOPT_POSTFIELDS => "{\n\t\"clave\": \"$key\","
            . "\n\t\"fecha\": \"2017-10-03T00:00:00-0600\","
            . "\n\t\"emisor\": {\n\t\t\"tipoIdentificacion\": \"02\",\n\t\t\"numeroIdentificacion\": \"3101123456\"\n\t},"
            . "\n\t\"receptor\": {\n\t\t\"tipoIdentificacion\": \"02\",\n\t\t\"numeroIdentificacion\": \"3101123456\"\n\t},"
            . "\n\t\"callbackUrl\": \"https://example.com/invoiceView\","
            . "\n\t\"comprobanteXml\": \"$invoice\"\n}",
          CURLOPT_COOKIE => "__cfduid=d73675273d6c68621736ad9329b7eff011507562303",
          CURLOPT_HTTPHEADER => array(
            "authorization: Bearer ".$authToken ,
            "content-type: application/json"
          ),
        ));
    
        $response = curl_exec($curl);
        $err = curl_error($curl);
        curl_close($curl);

        if ($err) {
          echo "cURL Error #:" . $err;
        } else {
            $response = json_decode($response);
        }
    }