<?php    

    function cb_encode($data = '', $key = '', $expiry = 0) /// $expiry must be in minutes
    {
        if(!$data)
        {
            return 'no data provided to encode';
        }

        if(!$key)
        {
            $key                    =   hash('sha256', config_item('jwt_token').config_item('id'), true);
        }
        else
        {
            $key                    =   hash('sha256', $key, true);
        }

        // $iv                         =   9999;

        $data                       =   strtr(base64_encode(gzdeflate(gzcompress(serialize(json_encode($data, JSON_HEX_APOS)),9))), '+/=', '-_,');
        $encodedData                =   rtrim(strtr(base64_encode(json_encode($data)), '+/', '-_'), '=');
        // $encodedData                =   base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $encodedData, MCRYPT_MODE_ECB, $iv));
        $encodedData                =   encrypt('aes-256-cbc', $key, $encodedData);

        if($expiry)
        {
            if(!is_numeric($expiry))
            {
                return 'Expiry must be a number in minutes';
            }

            $expiry_date_and_time   =   strtotime("+{$expiry} minutes");
            $encodedData            =   substr($encodedData, 0, 15) . config_item('jwt_token') . substr($encodedData, 15);
            $encodedData            =   cb_encode($expiry_date_and_time, 'expiry').'==='.$encodedData.config_item('jwt_token');
        }

        $encodedData                =   str_replace('+', 'pLuS', $encodedData);
        $encodedData                =   str_replace('/', 'FsLaSh', $encodedData);
        $encodedData                =   str_replace('=', 'pREQuElS', $encodedData);
        return $encodedData;
    }

    function encrypt($method, $key, $payload) {
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($method));
        $encrypted = @openssl_encrypt($payload, $method, $key, 0, $iv);
        return base64_encode($encrypted . '::' . $iv);
    }

    function decrypt($method, $key, $garble) {
        @list($encrypted_data, $iv) = explode('::', base64_decode($garble), 2);
        return @openssl_decrypt($encrypted_data, $method, $key, 0, $iv);
    }

    function cb_decode($token = '', $key = '', $invalidate = false, $debug = false)
    { 
        if(!$token)
        {
            if($debug)
            {
                return 'no encoded token was provided to decode';
            }
            return false;
        }

        if(!$key)
        {
            $key                    =   hash('sha256', config_item('jwt_token').config_item('id'), true);
        }
        else
        {
            $key                    =   hash('sha256', $key, true);
        }

        if($invalidate)
        {
            if(!token_validate_and_black_list($token))
            {
                if($debug)
                {
                    return 'Invalid or expired token';
                }
                return false;
            }
        }

        $token                      =   str_replace('pLuS', '+', $token);
        $token                      =   str_replace('FsLaSh', '/', $token);
        $token                      =   str_replace('pREQuElS', '=', $token);
        
        $token_array                =   explode('===', $token);
        
        if(isset($token_array[1]))
        {
            $expiry_time            =   cb_decode($token_array[0], 'expiry');

            if(strtotime('now') > $expiry_time)
            {
                if($debug)
                {
                    return 'Invalid or expired token';
                }
                return false;
            }

            $token                  =   str_replace(config_item('jwt_token'), '', $token_array[1]);
        }
        // $iv                         =   9999;
        $decodedData                =   decrypt( 'aes-256-cbc', $key, $token);
        // $decodedData                =   mcrypt_decrypt( MCRYPT_RIJNDAEL_256, $key, base64_decode( $token ), MCRYPT_MODE_ECB, $iv );
        $decodedData                =   json_decode(base64_decode(str_pad(strtr($decodedData, '-_', '+/'), strlen($decodedData) % 4, '=', STR_PAD_RIGHT)));
        
        if(empty($decodedData))
        {
            if($debug)
            {
                return 'Invalid token';
            }
            return false;
        }

        $decodedData                =   @unserialize(gzuncompress(gzinflate(base64_decode(strtr($decodedData, '-_,', '+/=')))));
        return json_decode($decodedData);
    }
    
    
    function token_validate_and_black_list($token = false)
    {
        if($token)
        {
            $file                               =   token_black_list_path('.jwt-black-lists.txt');
            
            if(!file_exists($file))
            {
                $token_black_list_path  =   $_SERVER['DOCUMENT_ROOT'].'/'.token_black_list_path();
                
                if(!file_exists($token_black_list_path))
                {
                    mkdir($token_black_list_path, 0777, true);
                }

                touch($_SERVER['DOCUMENT_ROOT'].'/'.$file);
            }
            
            $contents                           =   file_get_contents($file);
            $fileSize                           =   strlen($contents);

            if($fileSize > 20000000)
            {
                file_put_contents($file, "");
            }
            
            $pattern                            =   preg_quote($token, '/');
            $pattern                            =   "/^.*$pattern.*\$/m";

            if(preg_match_all($pattern, $contents))
            {
                return false;
            }
            
            file_put_contents($file, $token.PHP_EOL, FILE_APPEND | LOCK_EX);

            return true;
        }

        return false;
    }
    
