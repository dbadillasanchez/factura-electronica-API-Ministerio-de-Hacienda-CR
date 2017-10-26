<?php 
	public function parseBase64($invoice){
		//set $data to UTF-8 format
		$invoiceUTF8 = '';
	    $len = strlen($invoice);
	    for ($i = 0; $i < $len; $i++)
	    {
	        $invoiceUTF8 .=sprintf("%08b",ord($invoice{$i}));
	    }
	    //parse byte_array to base64
	    $base64 = base64_encode($invoiceUTF8);
	    return $base64;
	}
	
