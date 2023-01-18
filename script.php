<?php
date_default_timezone_set('America/Sao_Paulo');

class Segurancao{
    protected $admin_usuario;
    protected $admin_senha;
    protected $chave;
    protected $iv;
    protected $pasta_raiz;
    protected $pasta_dados;
    protected $pasta_arquvos;

    public function __construct($admin_usuario, $admin_senha, $chave, $iv, $pasta_raiz, $pasta_dados, $pasta_arquvos){
        $this->admin_usuario = sha1($admin_usuario);
        $this->admin_senha = sha1($admin_senha);
        $this->chave = md5($chave);
        $this->iv = $iv;
        
        if(substr_count($_SERVER["PHP_SELF"],"/")>=2):
            $this->caminho_arquivos = "../".$pasta_raiz.$pasta_arquvos."/";
            $this->caminho_dados = "../".$pasta_raiz.$pasta_dados."/";
        else:
            $this->caminho_arquivos = $pasta_raiz.$pasta_arquvos."/";
            $this->caminho_dados = $pasta_raiz.$pasta_dados."/";
        endif;
        
        if(!is_dir($this->caminho_arquivos)):
            mkdir($this->caminho_arquivos);
        endif;

        if(!is_dir($this->caminho_dados)):
            mkdir($this->caminho_dados);
        endif;
    }

    public function GUID(){
        if(function_exists('com_create_guid') === true):
            return trim(com_create_guid(), '{}');
        endif;
        return sprintf('%04X%04X-%04X-%04X-%04X-%04X%04X%04X', mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(16384, 20479), mt_rand(32768, 49151), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535));
    }
}

class Criptografia extends Segurancao{
    protected $dados;

    public function deDB($dados, $chave2 = NULL){
        $this->dados = $dados;
        if(isset($chave2)):
            $this->chave2 = $chave2;
            return openssl_decrypt(base64_decode($this->dados2), "AES-256-CBC", $this->chave, OPENSSL_RAW_DATA, $this->iv);
        else:
            return openssl_decrypt(base64_decode($this->dados), "AES-256-CBC", $this->chave, OPENSSL_RAW_DATA, $this->iv);
        endif;
    }

    public function enDB($dados, $chave2 = NULL){
        $this->dados = $dados;
        if(isset($chave2)):
            $this->chave2 = $chave2;
            return base64_encode(openssl_encrypt($this->dados2, "AES-256-CBC", $this->chave, OPENSSL_RAW_DATA, $this->iv));
        else:
            return base64_encode(openssl_encrypt($this->dados, "AES-256-CBC", $this->chave, OPENSSL_RAW_DATA, $this->iv));
        endif;
    }
}
