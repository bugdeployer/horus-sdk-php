<?php
declare(strict_types=1);
namespace Horus;

final class Recorder
{
    public array $events = [];
    private array $sources = [];
    private array $config;
    private array $redact;
    private string $id;
    private string $created;
    private int $started;
    private int $dropped = 0;
    private int $skipped = 0;
    private int $truncated = 0;
    private int $errors = 0;
    private int $eventBytes = 0;
    private ?string $endpoint;
    private string $spool;
    private int $deliveryDropped=0;

    public function __construct(private string $application, array $config = [])
    {
        $this->endpoint=$config['endpoint']??(getenv('HORUS_ENDPOINT')?:null);
        $this->spool=$config['spool_dir']??(getenv('HORUS_SPOOL_DIR')?:sys_get_temp_dir().'/horus-spool');
        unset($config['endpoint'],$config['spool_dir']);
        $this->label = substr((string)($config['label'] ?? 'capture'), 0, 120);
        unset($config['label']);
        if(array_diff(array_keys($config),['max_events','max_value_bytes','max_seconds','sample_rate','redaction','redact_keys','include','exclude']))throw new \InvalidArgumentException('Unknown capture option');
        $this->config = array_replace(['max_events'=>1000,'max_value_bytes'=>4096,'max_seconds'=>60,'sample_rate'=>1.0,'redaction'=>true,'redact_keys'=>[],'include'=>[],'exclude'=>[]], $config);
        $c = $this->config;
        if (!is_bool($c['redaction'])) throw new \InvalidArgumentException('redaction must be a boolean');
        if ($application === '' || strlen($application)>120 || !is_int($c['max_events']) || $c['max_events']<10 || $c['max_events']>2000 || !is_int($c['max_value_bytes']) || $c['max_value_bytes']<128 || $c['max_value_bytes']>8192 || !is_numeric($c['max_seconds']) || !is_finite((float)$c['max_seconds']) || $c['max_seconds']<.01 || $c['max_seconds']>300 || !is_numeric($c['sample_rate']) || $c['sample_rate']<0 || $c['sample_rate']>1) throw new \InvalidArgumentException('Invalid capture configuration');
        foreach (['redact_keys','include','exclude'] as $field) {
            if (!is_array($c[$field]) || count($c[$field])>30) throw new \InvalidArgumentException('Invalid capture terms');
            foreach ($c[$field] as $term) if (!is_string($term) || trim($term)==='' || strlen($term)>120) throw new \InvalidArgumentException('Invalid capture term');
        }
        $this->redact = $c['redaction'] ? array_merge(['password','secret','token','api_key','authorization','cookie'], array_map('strtolower',$c['redact_keys'])) : [];
        $this->id = self::uuid(); $this->created = gmdate('Y-m-d\TH:i:s\Z'); $this->started = hrtime(true);
    }
    private string $label;
    public static function uuid(): string {
        $b=random_bytes(16);$b[6]=chr((ord($b[6])&15)|64);$b[8]=chr((ord($b[8])&63)|128);
        $h=bin2hex($b);return substr($h,0,8).'-'.substr($h,8,4).'-'.substr($h,12,4).'-'.substr($h,16,4).'-'.substr($h,20);
    }
    private function sensitive(string $key):bool {foreach($this->redact as $term)if(str_contains(strtolower($key),$term))return true;return false;}
    private static function encode(mixed $value):string {return json_encode($value,JSON_THROW_ON_ERROR|JSON_INVALID_UTF8_SUBSTITUTE);}
    public function snapshot(mixed $value):mixed {
        $nodes=256;$limited=false;
        $clean=function(mixed $v,int $depth=0)use(&$clean,&$nodes,&$limited):mixed {
            if(--$nodes<0){$limited=true;return '[node limit]';}
            if(is_null($v)||is_bool($v)||is_int($v))return $v;
            if(is_float($v))return is_finite($v)?$v:(string)$v;
            if(is_string($v)){if(strlen($v)>1000){$limited=true;return substr($v,0,1000).'[truncated]';}return $v;}
            $isMap=is_object($v)&&get_class($v)==='stdClass';
            if($isMap)$v=get_object_vars($v);
            if(!is_array($v))return ['type'=>get_debug_type($v),'captured'=>false];
            if($depth>=5){$limited=true;return '[depth limit]';}
            $out=[];$n=0;$list=!$isMap&&array_is_list($v);
            foreach($v as $key=>$child){if($n++>=30){$limited=true;break;}$name=substr((string)$key,0,120);$next=$this->sensitive($name)?'[redacted]':$clean($child,$depth+1);if($list)$out[]=$next;else $out[$name]=$next;}
            return $list?$out:(object)$out;
        };
        $result=$clean($value);if(strlen(self::encode($result))>$this->config['max_value_bytes']){$limited=true;$result=(object)['truncated'=>true,'reason'=>'snapshot byte limit'];}
        if($limited)$this->truncated++;return $result;
    }
    public function allowed(string $block):bool {
        $included=!$this->config['include'];foreach($this->config['include'] as $term)if(str_contains($block,$term))$included=true;
        foreach($this->config['exclude'] as $term)if(str_contains($block,$term))return false;return $included;
    }
    public function emit(Scope $scope,string $kind,string $block,array $data,?string $parent=null,?string $source=null):void {
        try{
            if(!$scope->enabled)return;
            if(count($this->events)>=$this->config['max_events']||(hrtime(true)-$this->started)>$this->config['max_seconds']*1e9){$this->dropped++;return;}
            if(in_array($kind,['checkpoint','invariant'],true)&&$this->sensitive($block))foreach($data as $key=>$v)if($key!=='passed')$data[$key]='[redacted]';
            $event=['seq'=>count($this->events),'kind'=>$kind,'block'=>substr($block,0,240),'offset_us'=>intdiv(hrtime(true)-$this->started,1000),'trace_id'=>$scope->traceId,'span_id'=>$scope->spanId,'parent_id'=>$parent,'source_id'=>$source,'data'=>(object)$this->snapshot($data)];
            $bytes=strlen(self::encode($event));if($this->eventBytes+$bytes>2000000){$this->dropped++;return;}$this->eventBytes+=$bytes;$this->events[]=$event;
        }catch(\Throwable){$this->errors++;}
    }
    public function trace(string $name,callable $callback,array $metadata=[]):mixed {
        $enabled=(random_int(0,PHP_INT_MAX-1)/PHP_INT_MAX)<$this->config['sample_rate'];if(!$enabled)$this->skipped++;
        $scope=new Scope($this,self::uuid(),self::uuid(),$enabled);
        try{return $this->execute($scope,$name,['metadata'=>(object)$metadata],$callback);}
        finally{
            if($this->endpoint&&$enabled){try{
                if(!is_dir($this->spool))@mkdir($this->spool,0700,true);
                if(count(glob($this->spool.'/*.json*')?:[])>=32){$this->deliveryDropped++;}
                else{$capture=$this->export();$capture['id']=self::uuid();$capture['events']=array_values(array_filter($capture['events'],fn($e)=>$e['trace_id']===$scope->traceId));foreach($capture['events'] as $n=>&$event)$event['seq']=$n;unset($event);
                    $body=self::encode(['endpoint'=>$this->endpoint,'capture'=>$capture]);
                    if(strlen($body)>4000000){$this->deliveryDropped++;}else{$path=$this->spool.'/'.self::uuid();if(@file_put_contents($path.'.tmp',$body,LOCK_EX)!==false){@chmod($path.'.tmp',0600);@rename($path.'.tmp',$path.'.json');}else $this->deliveryDropped++;}
                }
            }catch(\Throwable){$this->deliveryDropped++;}}
        }
    }
    public function deliveryStatus():array{return ['queued'=>count(glob($this->spool.'/*.json')?:[]),'dropped'=>$this->deliveryDropped,'transport'=>'spool worker'];}
    public function execute(Scope $scope,string $name,array $inputs,callable $callback,?string $parent=null,?string $source=null,?callable $state=null):mixed {
        if($source!==null&&!isset($this->sources[$source]))throw new \InvalidArgumentException('Unknown source ID');
        $this->emit($scope,'call',$name,$inputs,$parent,$source);$start=hrtime(true);
        try{$value=$callback($scope);}
        catch(\Throwable $error){$this->emit($scope,'error',$name,['duration_us'=>intdiv(hrtime(true)-$start,1000),'error_type'=>get_class($error),'state'=>$state?$state():(object)[]],$parent,$source);throw $error;}
        $this->emit($scope,'return',$name,['duration_us'=>intdiv(hrtime(true)-$start,1000),'output'=>$value,'state'=>$state?$state():(object)[]],$parent,$source);return $value;
    }
    public function addSource(string $id,string $file,string $content,int $startLine=1):void {
        if(count($this->sources)>=100||isset($this->sources[$id])||strlen($id)>240||strlen($file)>500||strlen($content)>12000||$startLine<1)throw new \InvalidArgumentException('Invalid source excerpt');
        $safe=implode("\n",array_map(fn($line)=>$this->sensitive($line)?'[source line redacted]':$line,explode("\n",$content)));
        $this->sources[$id]=['id'=>$id,'file'=>$file,'start_line'=>$startLine,'content'=>$safe,'version'=>hash('sha256',$safe)];
    }
    private static function detached(mixed $v):mixed {if(is_array($v))return array_map(self::detached(...),$v);if($v instanceof \stdClass){$out=new \stdClass();foreach(get_object_vars($v) as $key=>$child)$out->$key=self::detached($child);return $out;}return $v;}
    public function export():array {return self::detached(['schema_version'=>1,'id'=>$this->id,'application'=>$this->application,'label'=>$this->label,'created_at'=>$this->created,'events'=>$this->events,'sources'=>array_values($this->sources),'dropped_events'=>$this->dropped,'skipped_traces'=>$this->skipped,'truncated_values'=>$this->truncated,'capture_errors'=>$this->errors,'config'=>$this->config]);}
    public function save(string $path):void {if(file_put_contents($path,self::encode($this->export()))===false)throw new \RuntimeException('Capture could not be saved');}
}

final class Scope
{
    public function __construct(private Recorder $recorder,public readonly string $traceId,public readonly string $spanId,public readonly bool $enabled=true){}
    public function span(string $name,array $inputs,callable $callback,?string $source=null,?string $className=null,?callable $state=null):mixed {
        if(!$this->recorder->allowed($name))return $callback($this);
        $child=new self($this->recorder,$this->traceId,Recorder::uuid(),$this->enabled);
        return $this->recorder->execute($child,$name,['inputs'=>(object)$inputs,'state'=>$state?$state():(object)[],'class_name'=>$className],$callback,$this->spanId,$source,$state);
    }
    public function checkpoint(string $name,mixed $value):mixed {$this->recorder->emit($this,'checkpoint',$name,['value'=>$value]);return $value;}
    public function expect(string $name,bool $condition,mixed $actual=null,mixed $expected=null):bool {$this->recorder->emit($this,'invariant',$name,['passed'=>$condition,'actual'=>$actual,'expected'=>$expected]);return $condition;}
    public function method(object $object,string $name,array $args=[],array $fields=[]):mixed {
        $state=static function()use($object,$fields):object{$values=[];foreach($fields as $field){if(!property_exists($object,$field))continue;$p=new \ReflectionProperty($object,$field);if($p->isPublic()&&!$p->isStatic()&&$p->isInitialized($object))$values[$field]=method_exists($p,'getRawValue')?$p->getRawValue($object):$p->getValue($object);}return (object)$values;};
        return $this->span(get_class($object).'.'.$name,['args'=>$args],fn()=> $object->$name(...$args),null,get_class($object),$state);
    }
}
