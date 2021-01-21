<?php

/* 
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

include 'sentinel_conf.php';


// init classes
$tail = new tail( $sentinel_logfile );
$sentinel = new sentinel( $sentinel_ignore , $sentinel_deny, $sentinel_maxcount, $sentinel_time);

echo "Sentinel v1.0 running!\n";
// main loop until Ctrl-C
while(1) {
    // get line
    $line = $tail->gets();
    
    if($line) {
        // if line contains text, parse it
        //echo $line;
        
        $sentinel->parse( $line );
        
    } else {    
        // else wait 1 second for next line
        sleep(1);
    }
}



class sentinel {
    
    var $data;
    var $maxcount;
    var $time;
    var $ignore;
    var $deny;
    
    function __construct( $ignore, $deny, $maxcount, $time ) {
       
       $this->data = null;
       
       $this->ignore = $ignore;
       $this->deny = $deny;
       
       $this->maxcount = $maxcount;    // aantal hammers
       $this->time = $time; //3600*10;   // 10 uur

    }
    
    
    function parse($str) {
        $exp = explode(' ', $str);
        
        //echo 'exp: '.json_encode($exp)."\n";
        
        // Invalid user
        if($exp[5]=='Invalid' && $exp[6]=='user') {
            // Invalid user detected
            //echo "Invalid user detected!\n";
            
            $this->addHost( $exp[9] );
        }
        
        // Failed password
        if($exp[5]=='Failed' && $exp[6]=='password') {
            // Invalid user detected
            //echo "Failed password detected!\n";

            if($exp[8] == 'invalid') {
                $this->addHost( $exp[12] );
            } else {
                $this->addHost( $exp[10] );
            }
        }
        
        // message repeated
        if($exp[5]=='message' && $exp[6]=='repeated' && $exp[10]=='Failed' && $exp[11]=='password') {
            // Invalid user detected
            //echo "Repeated failed password detected!\n";
            // do it twice :)
            $this->addHost( $exp[15] );
            $this->addHost( $exp[15] );
        }
            
    }
    
    private function punish($host) {
        $ptr = fopen($this->deny,'a');
        if($ptr) {
            echo "Punishing host $host!\n";
            fwrite($ptr, "ALL: $host\n");
            fclose($ptr);
        } else {
            echo "ERROR: Cannot append to $this->deny!\n";
            die;
        }
    }
    
    private function removeHost($host,$hostarray) {
        $this->data = null;
        
        foreach($hostarray as $item) {
            //echo "Iterating item : ".json_encode($item)."\n";
            if($host != $item['ip']) {
                // different host, copy
                $this->data[$item['ip']] = $item;
            }
        }
        //echo "DATA : ".json_encode($this->data)."\n";
    }
    
    private function matchIgnore($host) {
        foreach( $this->ignore as $item) {
            $comp = strpos($host, $item);
            //echo "compare '$item' with '$host' -> '$comp'\n";
            
            if($comp !== false && $comp == 0) {
                return(true);
            }
        }
        //no match, so no ignore
        return(false);
    }
    
    private function addHost($host) {
        // clean host
        $host = $this->strip($host);
        
        // check if on ignorelist and bailout if true
        if(self::matchIgnore($host)) {
            echo "Host ignored! ($host)\n";
            return;
        }
        
        // check if record exists
        if( !$this->data[$host]['first'] ) {
            $this->data[$host]['first'] = mktime();
            $this->data[$host]['counter'] = 0;
            $this->data[$host]['ip'] = $host;
            echo "New Record ($host)\n";
        }
        
        // check if record is within limits, if te lang geleden, reset counter
        if( mktime() > ($this->data[$host]['first'] + $this->time)) {
            
            $this->data[$host]['first'] = mktime();
            $this->data[$host]['counter'] = 0;
            echo "Reset Record ($host)\n";
        } 
            
        // increment hammer counter
        $this->data[$host]['counter'] += 1;
        //echo "DATA : ".json_encode($this->data)."\n";

        //check if host violates hammercount
        if($this->data[$host]['counter'] > $this->maxcount ) {
            $this->punish($host);
            $this->removeHost($host,$this->data);
        }
    }

    
    private function strip($str) {
        $var = str_replace("\n", '', $str);
        
        return($var);
    }
    
    
}




class tail {
    
    var $pos;
    var $ptr;
    var $filename;
    var $startsize;
    var $debug;
    var $firstrunDone;
    
    
    function __construct($file) {
        
        $this->debug = false;
        $this->filename = $file;
        $this->ptr = false;
        $this->pos = 0;
        
    }
    
    function enableDebug() {
        $this->debug = true;
    }
    
    function gets() {
        
        if(!$this->ptr) {
            $this->open();
        }
        
        $line = fgets($this->ptr);
        $this->pos = ftell($this->ptr);
        
        if(!$line && $this->ptr) {
            $this->close();
        }
        
        return($line);
    }
    
    private function open() {
        
        if(!$this->firstrunDone) {
            // skip file contents
            $this->pos = filesize($this->filename);
            $this->firstrunDone = true;
        }
        
        $this->ptr = fopen($this->filename, 'r');
        $data = fstat($this->ptr);
        $startsize = $data['size'];
        
        if($startsize < $this->startsize) {
            // truncated, seek to 0 bytes!
            $this->debug("File truncated, reloading from beginning");
            fseek($this->ptr, 0);
            
        } else {
            // normal, seek to $pos
            fseek($this->ptr, $this->pos);
            
        }
        $this->startsize = $startsize;
        $this->debug("File opened, current size : $this->startsize bytes, current pos : $this->pos");
        
    }
    
    private function close() {
        fclose($this->ptr);
        $this->ptr = false;
        $this->debug("File closed, current size : $this->startsize bytes, current pos : $this->pos");
    }
 
    
    function debug($str) {
        if($this->debug)
            echo "DEBUG : $str\n";
    }
    
}