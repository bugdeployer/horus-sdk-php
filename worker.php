<?php
declare(strict_types=1);
// Run beside PHP-FPM / the development server. No shell or app code is executed.
$directory=getenv('HORUS_SPOOL_DIR')?:sys_get_temp_dir().'/horus-spool';
$once=in_array('--once',$argv,true);
do{
    foreach(array_slice(glob($directory.'/*.json')?:[],0,32) as $file){
        $lock=@fopen($file,'r');if(!$lock||!flock($lock,LOCK_EX|LOCK_NB)){if($lock)fclose($lock);continue;}
        try{
            if(filesize($file)>4000000)throw new RuntimeException('Oversize spool');
            $item=json_decode(stream_get_contents($lock),true,512,JSON_THROW_ON_ERROR);
            $url=rtrim($item['endpoint'],'/').'/api/captures';
            if(!in_array(parse_url($url,PHP_URL_SCHEME),['http','https'],true))throw new RuntimeException('Invalid endpoint');
            $ok=false;
            for($attempt=0;$attempt<3;$attempt++){
                $context=stream_context_create(['http'=>['method'=>'POST','header'=>"Content-Type: application/json\r\nX-Horus-Delivery: automatic\r\n",'content'=>json_encode($item['capture'],JSON_THROW_ON_ERROR),'timeout'=>2,'ignore_errors'=>true,'follow_location'=>0]]);
                $response=@file_get_contents($url,false,$context,0,4096);
                $status=$http_response_header[0]??'';
                if(preg_match('/HTTP\/\S+ 2\d\d/',$status)){$ok=true;break;}
                if($attempt<2)usleep(250000*(2**$attempt));
            }
            flock($lock,LOCK_UN);fclose($lock);$lock=null;
            if($ok)@unlink($file);else {@rename($file,$file.'.failed');fwrite(STDERR,"Horus delivery failed; retained .failed spool file\n");}
        }catch(Throwable){if(is_resource($lock)){flock($lock,LOCK_UN);fclose($lock);}$lock=null;@rename($file,$file.'.failed');}
    }
    if(!$once)usleep(250000);
}while(!$once);
