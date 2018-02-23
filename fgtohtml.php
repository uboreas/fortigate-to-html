<?php

$logtag = false;
$lognode = false;
$logexpa = false;

function dolog($log, $tag, $s)
{
   if ($log)
      echo "log-".time()." - ".$tag." - ".$s."\n";
}

function addr_to_range($addr, $mask = "", &$v = false) {
    $a = $addr;
    $m = $mask;
    if (strpos($a, " ") !== false) {
       $x = explode(" ", $a);
       $a = $x[0];
       $m = $x[1];
    } else
    if (strpos($a, "/") !== false) {
       $x = explode("/", $a);
       $a = $x[0];
       $m = $x[1];
    }
    if ($m == "") {
       $m = "32";
    } else
    if (strpos($m, ".") !== false)
       $m = 32-log((ip2long($m) ^ ip2long('255.255.255.255')) + 1, 2);
    $a = ip2long(trim($a));
    $m = trim($m);
    $md = long2ip((-1 << (32 - (int)$m)));
    $ml = ip2long($md);
    $f = $a & $ml; // network
    $l = $a | (~$ml); // broadcast
    $fs = long2ip($f);
    $ls = long2ip($l);
    if ($v !== false) {
       $v["xfaddr"] = ip2long($fs);
       $v["xladdr"] = ip2long($ls);
       $v["xcount"] = $v["xladdr"] - $v["xfaddr"] + 1;
       return;
    }
    return $fs."-".$ls;
}

function port_to_range($pstr, $pfx = "", &$v = false) {
    $s = trim($pstr);
    $p = explode(" ", $s);
    for ($i = 0; $i < count($p); $i++) {
       $f = $p[$i];
       $l = $f;
       if (strpos($f, ":") !== false) {
          $x = explode(":", $f);
          $f = $x[0];
          $l = $f;
       }
       if (strpos($f, "-") !== false) {
          $x = explode("-", $f);
          $f = $x[0];
          $l = $x[1];
       }
       if ($v !== false) {
          $n = array();
          $n[0] = $f;
          $n[1] = $l;
          $v[$pfx][] = $n;
       }
    }
    return $s;
}

function local_utf8_decode($s)
{
   $a = iconv("UTF-8", "ISO-8859-1", $s);
   $b = iconv("UTF-8", "ISO-8859-1", $a);
   return iconv("ISO-8859-9", "UTF-8", $b);
}

function getindex($cft, &$xf)
{
   $c = count($xf);
   for ($i = 0; $i < $c; $i++) {
      if ($xf[$i] == $cft)
         return $i;
   }
   return false;
}

function getsingleval($l, $i)
{
   $x = substr(trim($l), $i);
   return ($x[0] == "\"") ? substr($x, 1, -1) : $x;
}

function getgroupval($l, $i)
{
   $x = str_replace("\\", "", str_replace("\" \"", chr(27), substr(trim($l), $i)));
   if ($x[0] == "\"")
      $x[0] = " ";
   if (strlen($x) >= 1) {
      if ($x[strlen($x)-1] == "\"")
         $x[strlen($x)-1] = " ";
   }
   $p = explode(chr(27), trim($x));
   $n = array();
   for ($i = 0; $i < count($p); $i++) 
      $n[] = $p[$i];
   return $n;
}

function object_is_any(&$t)
{
   if (!is_array($t)) {
      $s = strtolower($t);
      return (($s == "all") || ($s == "any")) ? true : false;
   }
   for ($i = 0; $i < count($t); $i++) {
      $s = strtolower($t[$i]);
      if (($s == "all") || ($s == "any"))
         return true;
   }
   return false;
}

function read_service($tag, &$v, &$xf)
{
   global $logtag;
   $n = array();
   $c = count($xf);
   $idx = getindex("config firewall service custom", $xf);
   if ($idx === false)
      return;
   for ($i = $idx; $i < $c; $i++) {
      $l = $xf[$i];
      if ($l == "end")
         break;
      if (trim($l) == "next")
         continue;
      if (substr(trim($l), 0, 5) === "edit ") {
         $nm = getsingleval($l, 5);
         $n["$nm"] = array();
         $n["$nm"]["type"] = "tcp/udp";
      } else
      if (substr(trim($l), 0, 13) === "set protocol ") {
         $n["$nm"]["type"] = getsingleval($l, 13);
      } else
      if (substr(trim($l), 0, 18) === "set tcp-portrange ") {
         $n["$nm"]["tcprange"] = getsingleval($l, 18);
      } else
      if (substr(trim($l), 0, 18) === "set udp-portrange ") {
         $n["$nm"]["udprange"] = getsingleval($l, 18);
      } else
      if (substr(trim($l), 0, 13) === "set category ") {
         $n["$nm"]["category"] = getsingleval($l, 13);
      } else
      if (substr(trim($l), 0, 13) === "set icmptype ") {
         $n["$nm"]["icmptype"] = getsingleval($l, 13);
      } else
      if (substr(trim($l), 0, 13) === "set icmpcode ") {
         $n["$nm"]["icmpcode"] = getsingleval($l, 13);
      } else
      if (substr(trim($l), 0, 20) === "set protocol-number ") {
         $n["$nm"]["protocol-number"] = getsingleval($l, 20);
      } else
      if (substr(trim($l), 0, 19) === "set explicit-proxy ") {
         $n["$nm"]["proxy"] = getsingleval($l, 19);
      } else
      if (substr(trim($l), 0, 12) === "set comment ") {
         $n["$nm"]["comment"] = getsingleval($l, 12);
      } else {
         dolog($logtag, "service tag", trim($l));
      }
   }
   $v[$tag] = $n;
}

function read_service_group($tag, &$v, &$xf)
{
   global $logtag;
   $c = count($xf);
   $idx = getindex("config firewall service group", $xf);
   if ($idx === false)
      return;
   for ($i = $idx; $i < $c; $i++) {
      $l = $xf[$i];
      if ($l == "end")
         break;
      if (trim($l) == "next")
         continue;
      if (substr(trim($l), 0, 5) === "edit ") {
         $nm = getsingleval($l, 5);
         $v[$tag]["$nm"] = array();
         $v[$tag]["$nm"]["type"] = "group";
      } else
      if (substr(trim($l), 0, 11) === "set member ") {
         $v[$tag]["$nm"]["members"] = getgroupval($l, 11);
      } else
      if (substr(trim($l), 0, 12) === "set comment ") {
         $v[$tag]["$nm"]["comment"] = getsingleval($l, 12);
      } else {
         dolog($logtag, "service group tag", trim($l));
      }
   }
}

function calc_service($tag, &$v)
{
   $k = array_keys($v[$tag]);
   $c = count($k);
   for ($i = 0; $i < $c; $i++) {
      $key = $k[$i];
      $n = $v[$tag][$key];
      if ($n["type"] == "tcp/udp") {
         if (isset($n["tcprange"]))
            port_to_range($n["tcprange"], "tcp", $v[$tag][$key]);
         if (isset($n["udprange"]))
            port_to_range($n["udprange"], "udp", $v[$tag][$key]);
      } else
      if ($n["type"] == "iprange") {
         $f = ip2long($n["firtsadr"]);
         $l = ip2long($n["lastadr"]);
         $v[$tag][$key]["xfaddr"] = $f;
         $v[$tag][$key]["xladdr"] = $l;
         $v[$tag][$key]["xcount"] = $l - $f + 1;
      } else
      if ($n["type"] == "pool") {
         $f = ip2long($n["startip"]);
         $l = ip2long($n["endip"]);
         $v[$tag][$key]["xfaddr"] = $f;
         $v[$tag][$key]["xladdr"] = $l;
         $v[$tag][$key]["xcount"] = $l - $f + 1;
      } else
      if ($n["type"] == "vip") {
         $tn = array();
         addr_to_range($n["extip"], "", $tn);
         $v[$tag][$key]["xfaddr"] = $tn["xfaddr"];
         $v[$tag][$key]["xladdr"] = $tn["xladdr"];
         $v[$tag][$key]["xcount"] = $tn["xladdr"] - $tn["xfaddr"] + 1;
         unset($tn);
         $tn = array();
         addr_to_range($n["mappedip"], "", $tn);
         $v[$tag][$key]["mxfaddr"] = $tn["xfaddr"];
         $v[$tag][$key]["mxladdr"] = $tn["xladdr"];
         $v[$tag][$key]["mxcount"] = $tn["xladdr"] - $tn["xfaddr"] + 1;
      }
   }
}

function read_service_category($tag, &$v, &$xf)
{
   global $logtag;
   $c = count($xf);
   $idx = getindex("config firewall service category", $xf);
   if ($idx === false)
      return;
   for ($i = $idx; $i < $c; $i++) {
      $l = $xf[$i];
      if ($l == "end")
         break;
      if (trim($l) == "next")
         continue;
      if (substr(trim($l), 0, 5) === "edit ") {
         $nm = getsingleval($l, 5);
         $v[$tag]["$nm"] = array();
         $v[$tag]["$nm"]["type"] = "category";
      } else
      if (substr(trim($l), 0, 12) === "set comment ") {
         $v[$tag]["$nm"]["comment"] = getsingleval($l, 12);
      } else {
         dolog($logtag, "service category tag", trim($l));
      }
   }
}

function read_address($tag, &$v, &$xf)
{
   global $logtag;
   $n = array();
   $c = count($xf);
   $idx = getindex("config firewall address", $xf);
   if ($idx === false)
      return;
   for ($i = $idx; $i < $c; $i++) {
      $l = $xf[$i];
      if ($l == "end")
         break;
      if (trim($l) == "next")
         continue;
      if (substr(trim($l), 0, 5) === "edit ") {
         $nm = getsingleval($l, 5);
         $n["$nm"] = array();
         $n["$nm"]["type"] = "subnet";
         if ($nm == "all") {
             $n["$nm"]["addr"] = "0.0.0.0";
             $n["$nm"]["mask"] = "0.0.0.0";
         }
      } else
      if (substr(trim($l), 0, 9) === "set type ") {
         $n["$nm"]["type"] = getsingleval($l, 9);
      } else
      if (substr(trim($l), 0, 12) === "set comment ") {
         $n["$nm"]["comment"] = getsingleval($l, 12);
      } else
      if (substr(trim($l), 0, 11) === "set subnet ") {
         $a = explode(" ", getsingleval($l, 11));
         $n["$nm"]["addr"] = $a[0];
         $n["$nm"]["mask"] = $a[1];
      } else
      if (substr(trim($l), 0, 13) === "set start-ip ") {
         $n["$nm"]["firtsadr"] = getsingleval($l, 13);
      } else
      if (substr(trim($l), 0, 11) === "set end-ip ") {
         $n["$nm"]["lastadr"] = getsingleval($l, 11);
      } else
      if (substr(trim($l), 0, 9) === "set fqdn ") {
         $n["$nm"]["fqdn"] = getsingleval($l, 9);
      } else
      if (substr(trim($l), 0, 25) === "set associated-interface ") {
         $n["$nm"]["interface"] = getsingleval($l, 25);
      } else {
         dolog($logtag, "address tag", trim($l));
      }
   }
   $v[$tag] = $n;
}

function read_address_group($tag, &$v, &$xf)
{
   global $logtag;
   $c = count($xf);
   $idx = getindex("config firewall addrgrp", $xf);
   if ($idx === false)
      return;
   for ($i = $idx; $i < $c; $i++) {
      $l = $xf[$i];
      if ($l == "end")
         break;
      if (trim($l) == "next")
         continue;
      if (substr(trim($l), 0, 5) === "edit ") {
         $nm = getsingleval($l, 5);
         $v[$tag]["$nm"] = array();
         $v[$tag]["$nm"]["type"] = "group";
      } else
      if (substr(trim($l), 0, 11) === "set member ") {
         $v[$tag]["$nm"]["members"] = getgroupval($l, 11);
      } else
      if (substr(trim($l), 0, 12) === "set comment ") {
         $v[$tag]["$nm"]["comment"] = getsingleval($l, 12);
      } else {
         dolog($logtag, "address group tag", trim($l));
      }
   }
}

function read_address_vip($tag, &$v, &$xf)
{
   global $logtag;
   $c = count($xf);
   $idx = getindex("config firewall vip", $xf);
   if ($idx === false)
      return;
   for ($i = $idx; $i < $c; $i++) {
      $l = $xf[$i];
      if ($l == "end")
         break;
      if (trim($l) == "next")
         continue;
      if (substr(trim($l), 0, 5) === "edit ") {
         $nm = getsingleval($l, 5);
         $v[$tag]["$nm"] = array();
         $v[$tag]["$nm"]["type"] = "vip";
      } else
      if (substr(trim($l), 0, 10) === "set extip ") {
         $v[$tag]["$nm"]["extip"] = getsingleval($l, 10);
      } else
      if (substr(trim($l), 0, 13) === "set mappedip ") {
         $v[$tag]["$nm"]["mappedip"] = getsingleval($l, 13);
      } else
      if (substr(trim($l), 0, 12) === "set extintf ") {
         $v[$tag]["$nm"]["extintf"] = getsingleval($l, 12);
      } else
      if (substr(trim($l), 0, 16) === "set portforward ") {
         $v[$tag]["$nm"]["portforward"] = getsingleval($l, 16);
      } else
      if (substr(trim($l), 0, 12) === "set extport ") {
         $v[$tag]["$nm"]["extport"] = getsingleval($l, 12);
      } else
      if (substr(trim($l), 0, 15) === "set mappedport ") {
         $v[$tag]["$nm"]["mappedport"] = getsingleval($l, 15);
      } else
      if (substr(trim($l), 0, 13) === "set protocol ") {
         $v[$tag]["$nm"]["protocol"] = getsingleval($l, 13);
      } else
      if (substr(trim($l), 0, 12) === "set comment ") {
         $v[$tag]["$nm"]["comment"] = getsingleval($l, 12);
      } else {
         dolog($logtag, "address vip tag", trim($l));
      }
   }
}

function read_address_pool($tag, &$v, &$xf)
{
   global $logtag;
   $c = count($xf);
   $idx = getindex("config firewall ippool", $xf);
   if ($idx === false)
      return;
   for ($i = $idx; $i < $c; $i++) {
      $l = $xf[$i];
      if ($l == "end")
         break;
      if (trim($l) == "next")
         continue;
      if (substr(trim($l), 0, 5) === "edit ") {
         $nm = getsingleval($l, 5);
         $v[$tag]["$nm"] = array();
         $v[$tag]["$nm"]["type"] = "pool";
      } else
      if (substr(trim($l), 0, 12) === "set startip ") {
         $v[$tag]["$nm"]["startip"] = getsingleval($l, 12);
      } else
      if (substr(trim($l), 0, 10) === "set endip ") {
         $v[$tag]["$nm"]["endip"] = getsingleval($l, 10);
      } else {
         dolog($logtag, "address pool tag", trim($l));
      }
   }
}

function read_ipsec_p1($tag, &$v, &$xf)
{
   global $logtag;
   $c = count($xf);
   $idx = getindex("config vpn ipsec phase1-interface", $xf);
   if ($idx === false)
      return;
   for ($i = $idx; $i < $c; $i++) {
      $l = $xf[$i];
      if ($l == "end")
         break;
      if (trim($l) == "next")
         continue;
      if (substr(trim($l), 0, 5) === "edit ") {
         $nm = getsingleval($l, 5);
         $v[$tag]["$nm"] = array();
      } else
      if (substr(trim($l), 0, 13) === "set proposal ") {
         $v[$tag]["$nm"]["algo"] = strtoupper(getsingleval($l, 13));
      } else
      if (substr(trim($l), 0, 10) === "set dhgrp ") {
         $v[$tag]["$nm"]["dhgrp"] = getsingleval($l, 10);
      } else
      if (substr(trim($l), 0, 14) === "set remote-gw ") {
         $v[$tag]["$nm"]["remote"] = getsingleval($l, 14);
      } else
      if (substr(trim($l), 0, 14) === "set interface ") {
         $v[$tag]["$nm"]["iface"] = getsingleval($l, 14);
      } else {
         dolog($logtag, "ipsec phase1 tag", trim($l));
      }
   }
}

function read_ipsec_p2($tag, &$v, &$xf)
{
   global $logtag;
   $c = count($xf);
   $idx = getindex("config vpn ipsec phase2-interface", $xf);
   if ($idx === false)
      return;
   for ($i = $idx; $i < $c; $i++) {
      $l = $xf[$i];
      if ($l == "end")
         break;
      if (trim($l) == "next")
         continue;
      if (substr(trim($l), 0, 5) === "edit ") {
         $nm = getsingleval($l, 5);
         $v[$tag]["$nm"] = array();
      } else
      if (substr(trim($l), 0, 15) === "set phase1name ") {
         $v[$tag]["$nm"]["p1"] = getsingleval($l, 15);
      } else
      if (substr(trim($l), 0, 13) === "set proposal ") {
         $v[$tag]["$nm"]["algo"] = strtoupper(getsingleval($l, 13));
      } else
      if (substr(trim($l), 0, 8) === "set pfs ") {
         $v[$tag]["$nm"]["pfs"] = getsingleval($l, 8);
      } else
      if (substr(trim($l), 0, 15) === "set src-subnet ") {
         $v[$tag]["$nm"]["srcsub"] = getsingleval($l, 15);
      } else
      if (substr(trim($l), 0, 17) === "set dst-start-ip ") {
         $v[$tag]["$nm"]["dstfadr"] = getsingleval($l, 17);
      } else {
         dolog($logtag, "ipsec phase2 tag", trim($l));
      }
   }
}

function read_policy($tag, &$v, &$xf)
{
   global $logtag;
   $n = array();
   $c = count($xf);
   $idx = getindex("config firewall policy", $xf);
   if ($idx === false)
      return;
   $rn = "1";
   for ($i = $idx; $i < $c; $i++) {
      $l = $xf[$i];
      if ($l == "end")
         break;
      if (trim($l) == "next")
         continue;
      if (substr(trim($l), 0, 5) === "edit ") {
         $nm = getsingleval($l, 5);
         $n["$nm"] = array();
         $n["$nm"]["index"] = $nm;
         $n["$nm"]["rulenum"] = $rn++;
         $n["$nm"]["action"] = "drop";
         $n["$nm"]["status"] = "enable";
         $n["$nm"]["asic"] = "enable";
         $n["$nm"]["capt"] = "disable";
      } else
      if (substr(trim($l), 0, 12) === "set srcintf ") {
         $n["$nm"]["srcintf"] = getgroupval($l, 12);
      } else
      if (substr(trim($l), 0, 12) === "set dstintf ") {
         $n["$nm"]["dstintf"] = getgroupval($l, 12);
      } else
      if (substr(trim($l), 0, 12) === "set srcaddr ") {
         $n["$nm"]["srcaddr"] = getgroupval($l, 12);
      } else
      if (substr(trim($l), 0, 12) === "set dstaddr ") {
         $n["$nm"]["dstaddr"] = getgroupval($l, 12);
      } else
      if (substr(trim($l), 0, 11) === "set action ") {
         $n["$nm"]["action"] = getsingleval($l, 11);
      } else
      if (substr(trim($l), 0, 13) === "set schedule ") {
         $n["$nm"]["schedule"] = getsingleval($l, 13);
      } else
      if (substr(trim($l), 0, 12) === "set service ") {
         $n["$nm"]["service"] = getgroupval($l, 12);
      } else
      if (substr(trim($l), 0, 11) === "set status ") {
         $n["$nm"]["status"] = getsingleval($l, 11);
      } else
      if (substr(trim($l), 0, 15) === "set logtraffic ") {
         $n["$nm"]["logtraffic"] = getsingleval($l, 15);
      } else
      if (substr(trim($l), 0, 11) === "set groups ") {
         $n["$nm"]["groups"] = getgroupval($l, 11);
      } else
      if (substr(trim($l), 0, 17) === "set global-label ") {
         $n["$nm"]["label"] = getsingleval($l, 17);
      } else
      if (substr(trim($l), 0, 8) === "set nat ") {
         $n["$nm"]["nat"] = getsingleval($l, 8);
      } else
      if (substr(trim($l), 0, 13) === "set poolname ") {
         $n["$nm"]["nataddr"] = getsingleval($l, 13);
      } else
      if (substr(trim($l), 0, 22) === "set auto-asic-offload ") {
         $n["$nm"]["asic"] = getsingleval($l, 22);
      } else
      if (substr(trim($l), 0, 19) === "set capture-packet ") {
         $n["$nm"]["capt"] = getsingleval($l, 19);
      } else
      if (substr(trim($l), 0, 13) === "set comments ") {
         $n["$nm"]["comment"] = getsingleval($l, 13);
      } else
      if (substr(trim($l), 0, 10) === "set users ") {
         $n["$nm"]["users"] = getsingleval($l, 10);
      } else {
         dolog($logtag, "policy tag", trim($l));
      }
   }
   $v[$tag] = $n;
}

function calc_address($tag, &$v)
{
   $k = array_keys($v[$tag]);
   $c = count($k);
   for ($i = 0; $i < $c; $i++) {
      $key = $k[$i];
      $n = $v[$tag][$key];
      if ($n["type"] == "subnet") {
         addr_to_range($n["addr"], $n["mask"], $v[$tag][$key]);
      } else
      if ($n["type"] == "iprange") {
         $f = ip2long($n["firtsadr"]);
         $l = ip2long($n["lastadr"]);
         $v[$tag][$key]["xfaddr"] = $f;
         $v[$tag][$key]["xladdr"] = $l;
         $v[$tag][$key]["xcount"] = $l - $f + 1;
      } else
      if ($n["type"] == "pool") {
         $f = ip2long($n["startip"]);
         $l = ip2long($n["endip"]);
         $v[$tag][$key]["xfaddr"] = $f;
         $v[$tag][$key]["xladdr"] = $l;
         $v[$tag][$key]["xcount"] = $l - $f + 1;
      } else
      if ($n["type"] == "vip") {
         $tn = array();
         addr_to_range($n["extip"], "", $tn);
         $v[$tag][$key]["xfaddr"] = $tn["xfaddr"];
         $v[$tag][$key]["xladdr"] = $tn["xladdr"];
         $v[$tag][$key]["xcount"] = $tn["xladdr"] - $tn["xfaddr"] + 1;
         unset($tn);
         $tn = array();
         addr_to_range($n["mappedip"], "", $tn);
         $v[$tag][$key]["mxfaddr"] = $tn["xfaddr"];
         $v[$tag][$key]["mxladdr"] = $tn["xladdr"];
         $v[$tag][$key]["mxcount"] = $tn["xladdr"] - $tn["xfaddr"] + 1;
      }
   }
}

function calc_address_covers_worker($tag, $o, $mf, $ml, &$v)
{
   if (object_is_any($o))
      return;
   $k = array_keys($v[$tag]);
   $c = count($k);
   for ($i = 0; $i < $c; $i++) {
      $key = $k[$i];
      $n = $v[$tag][$key];
      if ($o == $key)
         continue;
      if ($n['type'] == 'pool')
         continue;
      if ($n['type'] == 'vip')
         continue;
      if ((!isset($n["xfaddr"])) || (!isset($n["xladdr"])))
         continue;
      $tf = $n["xfaddr"];
      $tl = $n["xladdr"];
      if (($tf == $mf) && ($tl == $ml)) {
         $v["dup"][$o][] = $key;
      } else
      if (($tf >= $mf) && ($tl <= $ml)) {
         $v[$tag][$o]["covers"][$key] = $key;
      }
   }
}

function calc_address_covers($tag, &$v)
{
   $k = array_keys($v[$tag]);
   $c = count($k);
   for ($i = 0; $i < $c; $i++) {
      $key = $k[$i];
      $n = $v[$tag][$key];
      if (isset($n["xfaddr"]) && isset($n["xladdr"]))
         calc_address_covers_worker($tag, $key, $n["xfaddr"], $n["xladdr"], $v);
   }
}

function calc_address_group_covers_worker($tag, $o, $a, &$v, $ind = "  ")
{
   global $lognode;
   if (is_array($a)) {
      for ($i = 0; $i < count($a); $i++)
         calc_address_group_covers_worker($tag, $o, $a[$i], $v, $ind."  ");
   } else
   if ($a == $o) {
      return;
   } else
   if (isset($v["net"]["$a"])) {
      dolog($lognode, "c none", $ind." ".$o." -- ".$a);
      if ($v["net"]["$a"]["type"] == "group") {
         calc_address_group_covers_worker($tag, $a, $v["net"]["$a"]["members"], $v, $ind."  ");
      }
      $addobj = true;
      if (isset($v["net"]["$a"]["covers"])) {
         if (count($v["net"]["$a"]["covers"])) {
            $addobj = false;
            $k = array_keys($v["net"]["$a"]["covers"]);
            $c = count($k);
            for ($i = 0; $i < $c; $i++) {
               $key = $k[$i];
               $v["net"][$o]["covers"][$key] = $key;
               dolog($lognode, "c node", $ind." ".$o." << ".$key);
            }
         }
      }
      if ($addobj) {
         $v["net"][$o]["covers"][$a] = $a;
         dolog($lognode, "c node", $ind." ".$o." <- ".$a);
      }
   }
}

function calc_address_group_covers($tag, &$v)
{
   global $lognode;
   dolog($lognode, "c node", "started");
   $k = array_keys($v[$tag]);
   $c = count($k);
   for ($i = 0; $i < $c; $i++) {
      $key = $k[$i];
      $n = $v[$tag][$key];
      if ($n["type"] == "group") {
         dolog($lognode, "c root", "| ".$key);
         calc_address_group_covers_worker($tag, $key, $n["members"], $v);
      }
   }
}

function explode_network($a, &$v, &$n, $ind = "  ")
{
   global $logexpa;
   if (is_array($a)) {
      for ($i = 0; $i < count($a); $i++)
         explode_network($a[$i], $v, $n, $ind."  ");
   } else
   if (isset($v["net"]["$a"])) {
      if (isset($v["net"]["$a"]["covers"])) {
         dolog($logexpa, "c node", $ind." -> explode covers ".$a);
         $k = array_keys($v["net"]["$a"]["covers"]);
         for ($i = 0; $i < count($k); $i++) {
            $key = $k[$i];
            explode_network($key, $v, $n, $ind."  ");
         }
      } else {
         dolog($logexpa, "c node", $ind." >> explode ".$a);
         $n[$a] = $a;
      }
   }
}

function explode_service($a, &$v, &$n)
{
   if (is_array($a)) {
      for ($i = 0; $i < count($a); $i++)
         explode_service($a[$i], $v, $n);
   } else
   if (isset($v["svc"]["$a"])) {
      if ($v["svc"]["$a"]["type"] == "group") {
         for ($i = 0; $i < count($v["svc"]["$a"]["members"]); $i++)
            explode_service($v["svc"]["$a"]["members"][$i], $v, $n);
      } else {
         $n[] = $a;
      }
   }
}

function explode_policy($tag, &$v)
{
   global $logexpa;
   $k = array_keys($v["pol"]);
   $c = count($k);
   for ($i = 0; $i < count($k); $i++) {
      $key = $k[$i];
      $n = array();
      dolog($logexpa, "c node", " explode  src ".$key);
      explode_network($v["pol"]["$key"]["srcaddr"], $v, $n);
      $nk = array_keys($n);
      for ($j = 0; $j < count($nk); $j++)
         $v["pol"]["$key"]["xsrc"][] = $nk[$j];
      unset($n);
      $n = array();
      dolog($logexpa, "c node", " explode  dst ".$key);
      explode_network($v["pol"]["$key"]["dstaddr"], $v, $n);
      $nk = array_keys($n);
      for ($j = 0; $j < count($nk); $j++)
         $v["pol"]["$key"]["xdst"][] = $nk[$j];
      unset($n);
      $n = array();
      explode_service($v["pol"]["$key"]["service"], $v, $n);
      $v["pol"]["$key"]["xsvc"] = $n;
   }
}

function get_details_addr($s, &$v, &$ta = false)
{
   $r = "";
   if (isset($v["net"]["$s"]) && ($s != "all")) {
      $o = $v["net"]["$s"];
      $t = strtolower($o['type']);
      $tx = $t;
      if ($t == "subnet") {
         if ($o['mask'] == "255.255.255.255")
            $tx = "host";
      }
      $r.= 'Type     : '.$tx.'<br>';
      if ($t == "fqdn") {
         $r.= 'FQDN  : '.$o['fqdn'].'<br>';
         if (is_array($ta))
            $ta["addr"] = $o['fqdn'];
      } else
      if ($t == "group") {
         $cv = $o['members'];
         $r .= "Group Members :<br>";
         if (is_array($ta))
            $ta["memb"] = array();
         for ($i = 0; $i < count($cv); $i++) {
           $r .= "&nbsp;&nbsp;".$cv[$i].'<br>';
           if (is_array($ta))
              $ta["memb"][] = $cv[$i];
         }
      } else
      if ($t == "iprange") {
         $r.= 'IP First : '.$o['firtsadr'].'<br>';
         $r.= 'IP Last  : '.$o['lastadr'].'<br>';
         $r.= 'Coverage : '.$o['xcount'].' IPs<br>';
         if (is_array($ta)) {
            $ta["addr"] = "&nbsp;";
            $ta["rang"] = $o['firtsadr'].'-'.$o['lastadr'];
         }
      } else
      if ($t == "pool") {
         $r.= 'Pool Start IP : '.$o['startip'].'<br>';
         $r.= 'Pool End IP : '.$o['endip'].'<br>';
         $r.= 'Coverage : '.$o['xcount'].' IPs<br>';
         if (is_array($ta)) {
            $ta["addr"] = "&nbsp;";
            $ta["rang"] = $o['startip'].'-'.$o['endip'];
         }
      } else
      if ($t == "subnet") {
         if ($o['mask'] == "255.255.255.255") {
            $r.= 'IP Addr  : '.$o['addr'].'<br>';
            if (is_array($ta)) {
               $ta["addr"] = $o['addr'];
               $ta["rang"] = $o['addr']."-".$o['addr'];
            }
         } else {
            $r.= 'Network  : '.long2ip($o['xfaddr']).'<br>';
            $r.= 'Netmask  : '.$o['mask'].'<br>';
            $r.= 'IP Range : '.long2ip($o['xfaddr']).'-'.long2ip($o['xladdr']).'<br>';
            $r.= 'Coverage : '.$o['xcount'].' IPs<br>';
            if (is_array($ta)) {
               $ta["addr"] = long2ip($o['xfaddr'])."/".$o['mask'];
               $ta["rang"] = long2ip($o['xfaddr']).'-'.long2ip($o['xladdr']);
            }
         }
      } else
      if ($t == "vip") {
         $ip1 = long2ip($o['xfaddr']);
         $ip2 = long2ip($o['xladdr']);
         $xp1 = long2ip($o['mxfaddr']);
         $xp2 = long2ip($o['mxladdr']);
         if ($ip1 == $ip2) {
            $r.= 'Translate : '.$ip1.' => '.$xp1.'<br>';
            if (is_array($ta)) {
               $ta["addr"] = $ip1.' => '.$xp1;
               $ta["rang"] = "&nbsp;";
            }
         } else {
            $r.= 'Translate First : '.$ip1.' => '.$xp1.'<br>';
            $r.= 'Translate Last  : '.$ip2.' => '.$xp2.'<br>';
            $r.= 'Coverage : '.$o['xcount'].' IPs<br>';
            if (is_array($ta)) {
               $ta["addr"] = $ip1.' => '.$xp1;
               $ta["rang"] = $ip2.' => '.$xp2;
            }
         }
      } else
      if (is_array($ta)) {
         $ta["nat"] = "&nbsp;";
      }
      if (isset($o['covers'])) {
         $cv = $o['covers'];
         if ($t != "group")
            $r .= "Covered Objects :<br>";
         if (is_array($ta))
            $ta["covr"] = array();
         $kc = array_keys($o['covers']);
         for ($i = 0; $i < count($kc); $i++) {
            if ($t != "group")
               $r .= "&nbsp;&nbsp;".$kc[$i].'<br>';
            if (is_array($ta))
               $ta["covr"][] = $kc[$i];
         }
      }
    
   }
   return ($r != "") ? '<span><b>'.$s.'</b><br>'.$r.'</span>' : '';
}

function get_details_serv($s, &$v, &$ta = false)
{
   $r = "";
   if (isset($v["svc"]["$s"])) {
      $o = $v["svc"]["$s"];
      $t = strtolower($o['type']);
      $tx = strtoupper($o['type']);
      if (isset($o['tcp']) && (!isset($o['udp']))) {
         $tx = "TCP";
      } else
      if ((!isset($o['tcp'])) && isset($o['udp'])) {
         $tx = "UDP";
      } else
      if (isset($o['tcp']) && isset($o['udp'])) {
         $tx = "TCP/UDP";
      }
      $r.= 'Type     : '.$tx.'<br>';
      if (is_array($ta)) {
         $ta['type'] = $tx;
         $ta['prot'] = "&nbsp;";
         $ta['port'] = "";
         $ta['memb'] = array();
      }
      if (($t == "tcp/udp") || ($t == "ALL"))  {
         if (isset($o['tcp'])) {
            for ($i = 0; $i < count($o['tcp']); $i++) {
               $pr = ($o['tcp'][$i][0] == $o['tcp'][$i][1]) ? $o['tcp'][$i][0] : $o['tcp'][$i][0]."-".$o['tcp'][$i][1];
               $r .= 'TCP Port     : '.$pr.'<br>';
               if (is_array($ta))
                  $ta['port'] .= $pr."<br>";
            }
         }
         if (isset($o['udp'])) {
            for ($i = 0; $i < count($o['udp']); $i++) {
               $pr = ($o['udp'][$i][0] == $o['udp'][$i][1]) ? $o['udp'][$i][0] : $o['udp'][$i][0]."-".$o['udp'][$i][1];
               $r .= 'UDP Port     : '.$pr.'<br>';
               if (is_array($ta))
                  $ta['port'] .= $pr."<br>";
            }
         }
      } else
      if ($t == "icmp") {
         $ict = "ALL";
         if (isset($o['icmptype']))
            $ict = $o['icmptype'];
         $r .= 'ICMP Type: '.$ict.'<br>';
         if (is_array($ta))
            $ta['prot'] = $ict;
      } else
      if ($t == "ip") {
         $ict = "ALL";
         if (isset($o['protocol-number']))
            $ict = $o['protocol-number'];
         $r .= 'IP Protocol : '.$ict.'<br>';
         if (is_array($ta))
            $ta['prot'] = $ict;
      } else
      if ($t == "group") {
         $cv = $o['members'];
         $r .= "Group Members :<br>";
         for ($i = 0; $i < count($cv); $i++) {
           $r .= "&nbsp;&nbsp;".$cv[$i].'<br>';
           if (is_array($ta))
              $ta['memb'][] = $cv[$i];
         }
      }
      if (isset($o['comment'])) {
         $r .= 'Comment  : '.$o['comment'].'<br>';
         if (is_array(is_array($ta)))
            $ta["comm"] = $o['comment'];
      }
   }
   if (is_array($ta)) {
      if ($ta['port'] == "")
         $ta['port'] = "&nbsp;";
   }
   return ($r != "") ? '<span><b>'.$s.'</b><br>'.$r.'</span>' : '';
}

function rule_to_html_section($s)
{
   $r = '<tr class="sec"><td colspan="16">';
   $r .= local_utf8_decode($s);
   $r .= '</td></tr>';
   return $r;
}

function rule_to_html_row($s, $asrc, $adst, $asvc)
{
   $c = "";
   $l = 0;
   if ($asrc)
      ++$l;
   if ($adst)
      ++$l;
   if ($asvc)
      ++$l;
   if ($asrc && $asvc)
      $l = 7;
   if ($adst && $asvc)
      $l = 8;
   if ($asrc && $adst)
      $l = 9;
   if ($asrc && $adst && $asvc)
      $l = 10;
   if ($l > 0) {
      $c = ' class="x'.$l.'"';
   }
   if ($s == "disable")
      $c = ' class="dow"';
   $r = '<tr'.$c.'>';
   return $r;
}

function rule_to_html_cell($s, $px = "", $sx = "")
{
   if ($s == "_sep_") {
      $r .= '<td class="sep"></td>';
   } else
   if (is_array($s)) {
      $r .= '<td>';
      for ($i = 0; $i < count($s); $i++) {
         $r .= $px.local_utf8_decode($s[$i]).$sx.'<br>';
      }
      $r .= '</td>';
   } else {
      $r .= '<td>'.$px.local_utf8_decode($s).$sx.'</td>';
   }
   return $r;
}

function rule_to_html_cell_addr($s, &$v, $td = true, $pfx = "", $sfx = "")
{
   $r = "";
   if (is_array($s)) {
      if ($td)
         $r .= '<td><ul class="adr">';
      for ($i = 0; $i < count($s); $i++) {
         $r .= '<li class="tooltip">'.$pfx.local_utf8_decode($s[$i]).get_details_addr($s[$i], $v).$sfx.'</li>';
      }
      if ($td)
         $r .= '</ul></td>';
   } else {
      if ($td)
         $r .= '<td><ul class="adr">';
      $r .= '<li class="tooltip">'.$pfx.local_utf8_decode($s).get_details_addr($s, $v).$sfx.'</li>';
      if ($td)
         $r .= '</ul></td>';
   }
   return $r;
}

function rule_to_html_cell_serv($s, &$v)
{
   if (is_array($s)) {
      $r .= '<td><ul class="svc">';
      for ($i = 0; $i < count($s); $i++) {
         $r .= '<li class="tooltip">'.local_utf8_decode($s[$i]).get_details_serv($s[$i], $v).'</li>';
      }
      $r .= '</ul></td>';
   } else {
      $r .= '<td><ul class="svc"><li class="tooltip">'.local_utf8_decode($s).get_details_serv($s, $v).'</li></ul></td>';
   }
   return $r;
}

function rule_to_html_footer()
{
   $r = '</tbody></table>';
   return $r;
}

function adtr_to_html_cell(&$s, $ra, &$v)
{
   $em = '<td'.(($s["status"] == "disable") ? ' class="dow"' : '').">&nbsp</td>";
   if (!$ra)
      return $em;
   $p  = '<td><table><thead>';
   $p .= '<th>Source</th>';
   $p .= '<th>Destination</th>';
   $p .= '<th>Service</th>';
   $p .= '<th>NAT</th>';
   $p .= '</thead><tbody>';
   $t = "";
   $al = array();
   for ($i = 0; $i < count($s['dstaddr']); $i++) {
      $d = $s['dstaddr'][$i];
      if (isset($v["net"][$d])) {
          if ($v["net"][$d]['type'] == "vip") {
             $sc = array();
             $sl = $s['service'];
             $tp = $v["net"][$d]['extport'];
             for ($j = 0; $j < count($sl); $j++) {
                $o = $sl[$j];
                if ($o == "ALL") {
                   $sc[] = "ALL";
                   break;
                } else
                if (isset($v["svc"][$o])) {
                   for ($z = 0; $z < count($v["svc"][$o]["tcp"]); $z++) {
                      if (($tp >= $v["svc"][$o]["tcp"][$z][0]) && ($tp <= $v["svc"][$o]["tcp"][$z][1])) {
                         $sc[] = $o;
                      }
                   }
                   for ($z = 0; $z < count($v["svc"][$o]["udp"]); $z++) {
                      if (($tp >= $v["svc"][$o]["udp"][$z][0]) && ($tp <= $v["svc"][$o]["udp"][$z][1])) {
                         $sc[] = $o;
                      }
                   }
                }
             }
             if (count($sc) >= 1) {
                $n = array();
                $n['dst'] = $d;
                $n['adr'] = $v["net"][$d]['extip'];
                $n['map'] = $v["net"][$d]['mappedip'];
                $n['svc'] = $sc;
                $n['msv'] = $v["net"][$d]['mappedport'];
                $al[] = $n;
             }
          }
      }
   }
   $cx = " class=\"nat\"";
   if ($r['status'] == "disable")
      $cx = " class=\"dow\"";
   for ($i = 0; $i < count($al); $i++) {
      $t .= "<tr".$cx.">";
      $t .= rule_to_html_cell("= Source");
      $t .= rule_to_html_cell_addr($al[$i]['dst'], $v, true, "", " (".$al[$i]['adr'].")");
      $t .= rule_to_html_cell_serv($al[$i]['svc'], $v);
      $t .= rule_to_html_cell("Translate (".$al[$i]['map'].":".$al[$i]['msv'].")");
      $t .= "</tr>";
   }
   if ($s['nat'] == 'enable') {
      $t .= "<tr".$cx.">";
      $t .= rule_to_html_cell("= Source");
      $t .= rule_to_html_cell("= Destionation");
      $t .= rule_to_html_cell("= Service");
      $ah = true;
      if (isset($s['nataddr'])) {
         if ($s['nataddr'] != "") {
            $ah = false;
            $t .= rule_to_html_cell_addr($s['nataddr'], $v);
         }
      }
      if ($ah)
         $t .= rule_to_html_cell("Hide");
      $t .= "</tr>";
   }/* else {
      $t .= rule_to_html_cell("= Source");
      $t .= rule_to_html_cell("= Destionation");
      $t .= rule_to_html_cell("= Service");
      $t .= rule_to_html_cell("= Original");
   }*/
   if ($t == "")
      return $em;
   $p .= $t.'</tbody></table></td>';
   return $p;
}

function rule_to_html_header()
{
   $r = '<table><thead>';
   $r .= '<th>#</th>';
   $r .= '<th>ID</th>';
   $r .= '<th>Source Interface</th>';
   $r .= '<th>Destination Interface</th>';
   $r .= '<th>Source</th>';
   $r .= '<th>Destination</th>';
   $r .= '<th>Service</th>';
   $r .= '<th>Action</th>';
   $r .= '<th>Time</th>';
   $r .= '<th>Log</th>';
   $r .= '<th class="sep"></th>';
   $r .= '<th>X Src</th>';
   $r .= '<th>X Dst</th>';
   $r .= '<th>X Service</th>';
   $r .= '<th class="sep"></th>';
   $r .= '<th>Address Translation</th>';
   return $r.'</thead><tbody>';
}

function rule_to_html($s, $st, &$v)
{
   $r = "";
   if ($st != "")
      $r .= rule_to_html_section($st);
   $ra = ($s["action"] == "accept") ? true : false;
   $r .= rule_to_html_row($s["status"], object_is_any($s["srcaddr"]) && $ra, object_is_any($s["dstaddr"]) && $ra, object_is_any($s["service"]) && $ra);
   $r .= rule_to_html_cell($s["rulenum"]);
   $r .= rule_to_html_cell($s["index"]);
   $r .= rule_to_html_cell($s["srcintf"]);
   $r .= rule_to_html_cell($s["dstintf"]);
   $r .= rule_to_html_cell_addr($s["srcaddr"], $v);
   $r .= rule_to_html_cell_addr($s["dstaddr"], $v);
   $r .= rule_to_html_cell_serv($s["service"], $v);
   $r .= rule_to_html_cell($s["action"]);
   $r .= rule_to_html_cell($s["schedule"]);
   $r .= rule_to_html_cell($s["logtraffic"]);
   $r .= rule_to_html_cell("_sep_");
   $r .= rule_to_html_cell_addr($s["xsrc"], $v);
   $r .= rule_to_html_cell_addr($s["xdst"], $v);
   $r .= rule_to_html_cell_serv($s["xsvc"], $v);
   $r .= rule_to_html_cell("_sep_");
   $r .= adtr_to_html_cell($s, $ra, $v);
   $r .= '</tr>';
   return $r;
}

function export_rules($tag, &$v)
{
   $p = rule_to_html_header();
   $ls = "";
   $st = "";
   $k = array_keys($v["pol"]);
   $c = count($k);
   for ($i = 0; $i < count($k); $i++) {
      $key = $k[$i];
      if (isset($v["pol"]["$key"]["label"]))
         $st = $v["pol"]["$key"]["label"];
      $p .= rule_to_html($v["pol"]["$key"], ($st != $ls) ? $st : "", $v);
      $ls = $st;
   }
   $p .= rule_to_html_footer();
   return $p;
}

function export_address($s, &$v)
{
   if (!isset($v["$s"]))
      return "&nbsp;";
   $o = $v["$s"];
   $k = array_keys($o);
   $r = "<table><thead><th>#</th><th>Name</th>";
   $r .= "<th>Type</th><th>Address</th>";
   $r .= "<th>Range</th><th>Members</th><th>Covers</th>";
   $r .= "</thead><tbody>";
   $c = 1;
   for ($i = 0; $i < count($k); $i++) {
      $key = $k[$i];
      $ta = array();
      $oa = $key;
      if ($v[$s][$key]['type'] == "vip")
         continue;
      $r .= '<tr>';
      $r .= '<td>'.$c.'</td>';
      $r .= '<td><ul class="adr"><li class="tooltip">'.local_utf8_decode($oa).get_details_addr($oa, $v, $ta).'</li></ul></td>';
      $r .= '<td>'.$v[$s][$key]['type'].'</td>';
      $r .= '<td>'.$ta["addr"].'</td>';
      $r .= '<td>'.$ta["rang"].'</td>';
      $cv = "";
      if (count($ta["memb"])) {
         $cv .= rule_to_html_cell_addr($ta["memb"], $v, false);
      } else {
         $cv = "&nbsp;";
      }
      $r .= '<td><ul class="adr">'.$cv.'</ul></td>';
      $cv = "";
      if (count($ta["covr"])) {
         $cv .= rule_to_html_cell_addr($ta["covr"], $v, false);
      } else {
         $cv = "&nbsp;";
      }
      $r .= '<td><ul class="adr">'.$cv.'</ul></td>';
      $r .= '</tr>';
      ++$c;
   }
   return $r.'</tbody></table>';
}

function export_address_vip($s, &$v)
{
   if (!isset($v["$s"]))
      return "&nbsp;";
   $o = $v["$s"];
   $k = array_keys($o);
   $r = "<table><thead><th>#</th><th>Name</th>";
   $r .= "<th>Interface</th>";
   $r .= "<th>Address</th>";
   $r .= "<th>Port</th>";
   $r .= "<th>Mapped Address</th>";
   $r .= "<th>Mapped Port</th>";
   $r .= "</thead><tbody>";
   $c = 1;
   for ($i = 0; $i < count($k); $i++) {
      $key = $k[$i];
      $ta = array();
      $oa = $key;
      if ($v[$s][$key]['type'] != "vip")
         continue;
      $r .= '<tr>';
      $r .= '<td>'.$c.'</td>';
      $r .= '<td><ul class="adr"><li class="tooltip">'.local_utf8_decode($oa).get_details_addr($oa, $v, $ta).'</li></ul></td>';
      if (isset($v[$s][$key]['extintf'])) {
         $r .= '<td>'.$v[$s][$key]['extintf'].'</td>';
      } else {
         $r .= '<td>Any</td>';
      }
      $r .= '<td>'.$v[$s][$key]['extip'].'</td>';
      $r .= '<td>'.$v[$s][$key]['extport'].'</td>';
      $r .= '<td>'.$v[$s][$key]['mappedip'].'</td>';
      $r .= '<td>'.$v[$s][$key]['mappedport'].'</td>';
      $r .= '</tr>';
      ++$c;
   }
   return $r.'</tbody></table>';
}

function export_address_dup(&$v)
{
   if (!isset($v["dup"]))
      return "&nbsp;";
   $o = $v["dup"];
   $k = array_keys($o);
   $r = "<table><thead><th>Name</th>";
   $r .= "<th>Address</th>";
   $r .= "<th>Duplicates</th>";
   $r .= "</thead><tbody>";
   $c = 1;
   for ($i = 0; $i < count($k); $i++) {
      $key = $k[$i];
      $ta = array();
      $oa = $key;
      $r .= '<tr>';
      $r .= '<td>'.$oa.'</td>';
      get_details_addr($oa, $v, $ta);
      $r .= '<td>'.$ta["addr"].'</td>';
      $cv = "";
         for ($j = 0; $j < count($v["dup"][$key]); $j++) {
            $cv .= local_utf8_decode($v["dup"][$key][$j]).'<br>';
         }
      $r .= '<td>'.$cv.'</td>';
      $r .= '</tr>';
      ++$c;
   }
   return $r.'</tbody></table>';
}

function export_service($id, &$v)
{
   if (!isset($v["$id"]))
      return "&nbsp;";
   $o = $v["$id"];
   $k = array_keys($o);
   $r = "<table><thead><th>#</th><th>Name</th><th>Type</th><th>Proto</th><th>Port</th><th>Comment</th><th>Members</th>";
   $r .= "</thead><tbody>";
   $c = 1;
   for ($i = 0; $i < count($k); $i++) {
      $key = $k[$i];
      $obj = $o[$key];
      $r .= '<tr>';
      $r .= '<td>'.$c.'</td>';
      $ta = array();
      $r .= '<td><ul class="adr"><li class="tooltip">'.local_utf8_decode($key).get_details_serv($key, $v, $ta).'</li></ul></td>';
      $r .= '<td>'.$ta["type"].'</td>';
      $r .= '<td>'.$ta["prot"].'</td>';
      $r .= '<td>'.$ta["port"].'</td>';
      $r .= '<td>'.$ta["comm"].'</td>';
      if (count($ta["memb"])) {
         $r .= rule_to_html_cell_serv($ta["memb"], $v);
      } else {
         $r .= "<td>&nbsp;</td>";
      }
      $r .= '</tr>';
      ++$c;
   }
   return $r.'</tbody></table>';
}

function encrd_get_prop(&$o, $a, $t, $pfx = "") {
   if (!isset($o[$a]))
      return '<li>'.$t.' : <i>not configured</i></li>';
   return '<li>'.$t.' : '.$pfx.$o[$a].'</li>';
}

function find_covering_addr($s, &$v)
{
   $mf = $s["xfaddr"];
   $ml = $s["xladdr"];
   $k = array_keys($v["net"]);
   $c = count($k);
   $r = array();
   for ($i = 0; $i < $c; $i++) {
      $key = $k[$i];
      $n = $v["net"][$key];
      if (isset($n["xfaddr"]) && isset($n["xladdr"])) {
         $tf = $n["xfaddr"];
         $tl = $n["xladdr"];
         if (($tf >= $mf) && ($tl <= $ml))
            $r[] = $key;
      }
   }
   return $r;
}

function export_ipsec(&$v)
{
   if (!isset($v["vpn1"]))
      return "&nbsp;";
   $r  = "<table><thead>";
   $r .= "<th>#</th><th>Name</th><th>Config</th><th>IKE Phase 1</th><th>IKE Phase 2</th><th>Source</th><th>Destination</th>";
   $r .= "</thead><tbody>";
   $o = $v["vpn2"];
   $k = array_keys($o);
   $c = 1;
   for ($i = 0; $i < count($k); $i++) {
      $key = $k[$i];
      $obj = $o[$key];
      $par = $obj['p1'];
      $pbj = false;
      if (isset($v['vpn1'][$par]))
         $pbj = $v['vpn1'][$par];
      if (!$pbj)
         continue;
 
      $r .= '<tr>';
      $r .= '<td>'.$c.'</td>';
      $r .= '<td>'.$par.'</td>';

      $t = '<ul class="adr">';
      $t .= encrd_get_prop($pbj, "iface", "Interface");
      $t .= encrd_get_prop($pbj, "remote", "IP Address");
      $t .= '</ul>';
      $r .= '<td>'.$t.'</td>';

      $t = '<ul class="adr">';
      $t .= encrd_get_prop($pbj, "dhgrp", "DH Group", "Group ");
      $t .= encrd_get_prop($pbj, "algo", "Encryption Algorithm");
      $t .= '</ul>';
      $r .= '<td>'.$t.'</td>';

      $t = '<ul class="adr">';
      $t .= encrd_get_prop($obj, "algo", "Encryption Algorithm");
      $t .= encrd_get_prop($obj, "pfs", "Perfect Secrecy");
      $t .= '</ul>';
      $r .= '<td>'.$t.'</td>';

      $sn = array(); 
      addr_to_range($obj['srcsub'], "", $sn);
      $sl = find_covering_addr($sn, $v);
      if (count($sl)) {
         $r .= rule_to_html_cell_addr($sl, $v);
      } else {
         $r .= '<td>&nbsp;</td>';
      }
      unset($sn);
      $sn = array(); 
      addr_to_range($obj['dstfadr'], "", $sn);
      $sl = find_covering_addr($sn, $v);
      if (count($sl)) {
         $r .= rule_to_html_cell_addr($sl, $v);
      } else {
         $r .= '<td>&nbsp;</td>';
      }
      $r .= '</tr>';
      ++$c;
   }
   return $r.'</tbody></table>';
}

function create_html_header(&$v)
{
   $r = '<html>';
   $r .= '<head>';
   $r .= '<meta http-equiv="Content-Type" content="text/html; charset=utf-8">';
   $r .= '<style type=text/css>';
   $r .= '<!--';
   $r .= 'body { margin: 10px; font-family: sans-serif; } ';
   $r .= 'table { border-collapse: collapse; border-spacing: 0px; font-size: 80%; } ';
   $r .= 'th { padding: 10px; border: 1px solid #999; vertical-align: top; text-align: center; background: #d0d0fe; } ';
   $r .= 'td { padding: 10px; border: 1px solid #999; vertical-align: top; text-align: left;} ';
   $r .= '.sec td { background: #fefed0; } ';
   $r .= '.x1 td { background: #ffeeee; } ';
   $r .= '.x2 td { background: #ffdddd; } ';
   $r .= '.x3 td { background: #ffcccc; } ';
   $r .= '.x7 td { background: #ffbbbb; } ';
   $r .= '.x8 td { background: #ffaaaa; } ';
   $r .= '.x9 td { background: #ff9999; } ';
   $r .= '.x10 td { background: #ff7777; } ';
   $r .= '.dow td { background: #e8e8e8; text-decoration: line-through; } ';
   $r .= '.nat td { background-color:rgba(255, 255, 255, 0.80); white-space: nowrap; } ';
   $r .= 'th.sep { background: #909090; padding: 1px; } ';
   $r .= 'td.sep { background: #909090; padding: 1px; } ';
   $r .= 'ul.adr { list-style: none; margin: 0px; padding: 0px; } ';
   $r .= '.adr li { padding: 0px; margin: 0px; } ';
   $r .= 'ul.svc { list-style: none; margin: 0px; padding: 0px; } ';
   $r .= '.svc li { padding: 0px; margin: 0px; } ';
   $r .= 'li.tooltip { outline: none; } ';
   $r .= 'li.tooltip span { z-index:10; display:none; padding:10px 15px; margin-top:-10px; margin-left:10px; width:300px; font-size: 90%; font-family: Courier, monospace; line-height: 130%; } ';
   $r .= 'li.tooltip:hover span { display:inline; position:absolute; color:#111; border:1px solid #DCA; background:#fffAF0; } ';
   $r .= '.callout { z-index:20;position:absolute;top:30px;border:0;left:-12px; } ';
   $r .= 'li.tooltip span { border-radius:4px; box-shadow: 5px 5px 8px #CCC; } ';
   $r .= '.ttab { font-family: tahoma, helvetica; font-size: 90%; text-align: center; padding: 0px; margin: 0px; display: -moz-inline-stack; display: inline-block; zoom: 1; *display: inline; } ';
   $r .= 'ul.ttab { list-style: none; white-space: nowrap; margin: 0px; padding: 0px; } ';
   $r .= '.ttab li { float: left; margin: 0px 5px 0px 0px; padding: 3px 5px 3px 5px; border-top: 1px solid #f5f5f5; border-left: 1px solid #f5f5f5; border-right: 1px solid #C5C5C5; border-bottom: 1px solid #C5C5C5; cursor: pointer; min-width: 70px; } ';
   $r .= '.ttab li:hover { border-right: 1px solid #BABABA; border-bottom: 1px solid #BABABA; } ';
   $r .= '.ttab li:active, li.ttabact { border-top: 1px solid #a5a5a5; border-left: 1px solid #a5a5a5; border-right: 1px solid #fafafa; border-bottom: 1px solid #fafafa; padding: 3px 4px 3px 6px; } ';
   $r .= '#tabrule { display: block; } ';
   $r .= '#tabsobj { display: none; } ';
   $r .= '#tabsrvc { display: none; } ';
   $r .= '#tabaobj { display: none; } ';
   $r .= '#tabvpns { display: none; } ';
   $r .= '-->';
   $r .= '</style>';
   $r .= '<script type="text/javascript">';
   $r .= "   function showblock(lid) {
      document.getElementById('tabrule').style.display = 'none';
      document.getElementById('rule').classList.remove('ttabact');
      document.getElementById('tabsobj').style.display = 'none';
      document.getElementById('sobj').classList.remove('ttabact');
      document.getElementById('tabsrvc').style.display = 'none';
      document.getElementById('srvc').classList.remove('ttabact');
      document.getElementById('tabaobj').style.display = 'none';
      document.getElementById('aobj').classList.remove('ttabact');
      document.getElementById('tabvpns').style.display = 'none';
      document.getElementById('vpns').classList.remove('ttabact');
      var eid = document.getElementById('tab'+lid);
      eid.style.display = 'block';
      document.getElementById(lid).classList.add('ttabact');
   } ";
   $r .= '</script>';
   $r .= '</head>';
   $r .= '<body>';
   return $r;
}

function create_html_footer(&$v)
{
   return '</body></html>';
}

function cunstruct_html(&$v)
{
   $r  = '<div style="text-align: left;">&nbsp;&nbsp;<ul class="ttab">';
   $r .= '<li onclick="showblock(this.id)" id="rule">Rules</li>';
   //$r .= '<li onclick="showblock(this.id)" id="objs">Objects</li>';
   $r .= '<li onclick="showblock(this.id)" id="aobj">Address Objects</li>';
   $r .= '<li onclick="showblock(this.id)" id="sobj">Static-NATed Objects</li>';
   $r .= '<li onclick="showblock(this.id)" id="srvc">Service Objects</li>';
   $r .= '<li onclick="showblock(this.id)" id="vpns">Site-to-Site VPN</li>';

   $r .= '</ul><br><br></div>';
   $r .= '<div id="tabrule">'.$v["html_rules"].'</div>';
   $r .= '<div id="tabaobj">'.$v["html_aobjs"].'</div>';
   $r .= '<div id="tabsobj">'.$v["html_sobjs"].'</div>';
   $r .= '<div id="tabsrvc">'.$v["html_srvcs"].'</div>';
   $r .= '<div id="tabvpns">'.$v["html_vpnss"].'</div>';

   return $v["html_header"].$r.$v["html_footer"];
}

if (!isset($argv[1])) {
   echo "Usage: ".$argv[0]." <config file>\n\n";
   exit;
}

$cf = $argv[1];
$xf = explode("\n", file_get_contents($cf));
$v = array();
read_service("svc", $v, $xf);
read_service_group("svc", $v, $xf);
calc_service("svc", $v);
read_address("net", $v, $xf);
read_address_group("net", $v, $xf);
read_address_vip("net", $v, $xf);
read_address_pool("net", $v, $xf);
read_ipsec_p1("vpn1", $v, $xf);
read_ipsec_p2("vpn2", $v, $xf);
read_policy("pol", $v, $xf);
calc_address("net", $v);
calc_address_covers("net", $v);
calc_address_group_covers("net", $v);
explode_policy("pol", $v);

$v["html_header"] = create_html_header($v);
$v["html_footer"] = create_html_footer($v);
$v["html_rules"] = export_rules("pol", $v);
//$v["html_tobjs"] = table_from_list_addr("__all_used_net_addresses", "attrib", $v);
$v["html_aobjs"] = export_address("net", $v);
$v["html_sobjs"] = export_address_vip("net", $v);
//$v["html_sobjs"] .= "<br><br>".export_address_dup($v);
$v["html_srvcs"] = export_service("svc", $v);
$v["html_vpnss"] = export_ipsec($v);

$r = cunstruct_html($v);
file_put_contents($cf.".html", $r);
/*
file_put_contents($cf.".array.svc.txt", print_r($v["svc"], true));
file_put_contents($cf.".array.net.txt", print_r($v["net"], true));
file_put_contents($cf.".array.pol.txt", print_r($v["pol"], true));
file_put_contents($cf.".array.dup.txt", print_r($v["dup"], true));
file_put_contents($cf.".array.vp1.txt", print_r($v["vpn1"], true));
file_put_contents($cf.".array.vp2.txt", print_r($v["vpn2"], true));
*/

echo "netobj ".count($v["net"])."\n";
echo "svcobj ".count($v["svc"])."\n";
echo "> ".$cf.".html created\n\n";

?>
