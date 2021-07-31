<?php  

#http://www.enye-sec.org/textos/jugando.con.los.sockets.%28port.scanning%29.txt

#puertos de nmap https://svn.nmap.org/nmap/nmap-services
#rangos de ip de todo mexico: http://www.vitessenetworks.com.mx/recursos/38-tips-tecnicos/31--direcciones-ip-publicas-en-mexico
#api whois http://whois.domaintools.com/qedu.mx

error_reporting(0);
class portscan
{

	public $ping=1;

	#Tiempo de tolerancia para contestar el puerto
	public $tiempo=0.5;
	



	#Puertos que se escanearans  #puertos de nmap https://svn.nmap.org/nmap/nmap-services
	public $Apuertos=array(array(1,"tcp","tcpmux"),array(5,"tcp","rje"),array(7,"tcp","echo"),array(9,"tcp","discard"),array(11,"tcp","systat"),array(13,"tcp","daytime"),array(17,"tcp","qotd"),array(18,"tcp","msp "),array(19,"tcp","chargen "),array(20,"tcp","ftp-data"),array(21,"tcp","ftp "),array(22,"tcp","ssh "),array(23,"tcp","telnet "),array(25,"tcp","smtp "),array(26,"tcp","rsftp"),array(37,"tcp","time "),array(39,"tcp","rlp "),array(42,"tcp","nameserver"),array(43,"tcp","nickname"),array(49,"tcp","tacacs "),array(50,"tcp","re-mail-ck "),array(53,"tcp","domain"),array(53,"udp","DNS "),array(63,"tcp","whois"),array(66,"tcp"," Oracle SQLNet"),array(67,"udp","bootps"),array(68,"udp","bootpc"),array(69,"udp","tftp "),array(70,"tcp","gopher"),array(79,"tcp","finger"),array(80,"tcp","http "),array(88,"tcp","kerberos "),array(95,"tcp","supdup"),array(101,"tcp","hostname "),array(107,"tcp","rtelnet"),array(109,"tcp","pop2 "),array(110,"tcp","pop3"),array(111,"tcp","sunrpc"),array(113,"tcp","auth"),array(115,"tcp","sftp"),array(117,"tcp","uupc-path"),array(119,"tcp","nntp"),array(123,"udp","ntp "),array(135,"tcp","epmap "),array(137,"udp","netbios-ns"),array(138,"udp","netbios-dgm "),array(139,"tcp","netbios-ssn "),array(143,"tcp","imap "),array(161,"udp","snmp "),array(162,"udp","snmptrap "),array(174,"tcp","mailq "),array(177,"tcp","xdmcp "),array(178,"tcp","nextstep"),array(179,"tcp","bgp "),array(194,"tcp","irc "),array(199,"tcp","smux "),array(201,"tcp","at-rtmp "),array(202,"tcp","at-nbp"),array(204,"tcp","at-echo "),array(206,"tcp","at-zis"),array(209,"tcp","qmtp "),array(210,"tcp","z39.50"),array(213,"tcp","ipx "),array(220,"tcp","imap3"),array(245,"tcp","link "),array(347,"tcp","fatserv"),array(363,"tcp","rsvp_tunnel "),array(369,"tcp","rpc2portmap"),array(370,"tcp","codaauth2 "),array(372,"tcp","ulistproc "),array(389,"tcp","ldap"),array(427,"tcp","svrloc "),array(434,"tcp","mobileip-agent"),array(435,"tcp","mobilip-mn"),array(443,"tcp","https "),array(444,"tcp","snpp"),array(445,"tcp","microsoft-ds"),array(465,"tcp","smtps"),array(500,"udp","IPSec "),array(512,"tcp","exec"),array(513,"tcp","Rlogin"),array(514,"udp","syslog"),array(515,"tcp","usado para la impresión en windows"),array(520,"udp","rip"),array(554,"tcp","rtsp-tcp"),array(587,"tcp","smtp "),array(591,"tcp","FileMaker 6.0 "),array(631,"tcp","CUPS"),array(666,"tcp","dom juesgos"),array(690,"tcp","VATP "),array(851,"tcp","unknown"),array(957,"tcp","unknown"),array(993,"tcp","imaps"),array(995,"tcp","POP3s"),array(1025,"tcp","NFS-or-IIS"),array(1080,"tcp","SOCKS "),array(1337,"tcp","comprometidas o infectadas"),array(1352,"tcp","IBM Lotus Notes/Domino RCP"),array(1433,"tcp","Microsoft-SQL-Server"),array(1434,"tcp","Microsoft-SQL-Monitor"),array(1494,"tcp","Citrix MetaFrame Cliente ICA"),array(1512,"tcp","WINS Windows Internet Naming Service"),array(1521,"tcp","Oracle listener por defecto"),array(1701,"udp","Enrutamiento y Acceso Remoto para VPN con L2TP."),array(1720,"udp","H.323"),array(1723,"tcp","Enrutamiento y Acceso Remoto para VPN con PPTP."),array(1761,"tcp","Novell Zenworks Remote Control utility"),array(1863,"tcp","MSN Messenger"),array(1935,"tcp","FMS Flash Media Server"),array(2049,"tcp","NFS Archivos del sistema de red"),array(2082,"tcp","cPanel puerto por defecto"),array(2083,"tcp","CPanel puerto por defecto sobre SSL"),array(2086,"tcp","Web Host Manager puerto por defecto"),array(2087,"tcp","https-simple-new"),array(2030,"tcp","device2"),array(2121,"tcp","Puerto Opcional de FTP"),array(2222,"tcp","Puerto Opcional de SSH"),array(2427,"udp","Cisco MGCP"),array(2525,"tcp","ms-v-worlds"),array(3000,"tcp","http-simple-new"),array(3030,"tcp","NetPanzer"),array(3074,"tcp","Xbox Live"),array(3074,"udp","Xbox Live"),array(3128,"tcp","HTTP usado por web caches y por defecto en Squid cache"),array(3128,"tcp","NDL-AAS"),array(3306,"tcp","MySQL sistema de gestión de bases de datos"),array(3389,"tcp","RDP (Remote Desktop Protocol) Terminal Server"),array(3396,"tcp","Novell agente de impresión NDPS"),array(3690,"tcp","Subversion (sistema de control de versiones)"),array(4662,"tcp","eMule (aplicación de compartición de ficheros)"),array(4672,"udp","eMule (aplicación de compartición de ficheros)"),array(4899,"tcp","RAdmin (Remote Administrator), herramienta de administración remota (normalmente troyanos)"),array(5000,"tcp","Universal plug-and-play"),array(5060,"udp","Protocol (SIP)"),array(5190,"tcp","AOL y AOL Instant Messenger"),array(5222,"tcp","Jabber/XMPP conexión de cliente"),array(5223,"tcp","Jabber/XMPP puerto por defecto para conexiones de cliente SSL"),array(5269,"tcp","Jabber/XMPP conexión de servidor"),array(5432,"tcp","PostgreSQL sistema de gestión de bases de datos"),array(5517,"tcp","Setiqueue proyecto SETI@Home"),array(5631,"tcp","PC-Anywhere protocolo de escritorio remoto"),array(5632,"udp","PC-Anywhere protocolo de escritorio remoto"),array(5400,"tcp","VNC protocolo de escritorio remoto (usado sobre HTTP)"),array(5500,"tcp","VNC protocolo de escritorio remoto (usado sobre HTTP)"),array(5600,"tcp","VNC protocolo de escritorio remoto (usado sobre HTTP)"),array(5700,"tcp","VNC protocolo de escritorio remoto (usado sobre HTTP)"),array(5800,"tcp","VNC protocolo de escritorio remoto (usado sobre HTTP)"),array(5900,"tcp","VNC protocolo de escritorio remoto (conexión normal)"),array(5985,"tcp","http-simple-new"),array(6000,"tcp","X11 usado para X-windows"),array(6112,"udp","Blizzard"),array(6129,"tcp","Dameware Software conexión remota"),array(6346,"tcp","Gnutella compartición de ficheros (Limewire, etc.)"),array(6347,"udp","Gnutella"),array(6348,"udp","Gnutella"),array(6349,"udp","Gnutella"),array(6350,"udp","Gnutella"),array(6355,"udp","Gnutella"),array(6667,"tcp","IRC IRCU Internet Relay Chat"),array(6881,"tcp","BitTorrent puerto por defecto"),array(6969,"tcp","BitTorrent puerto de tracker"),array(7100,"tcp","Servidor de Fuentes X11"),array(7547,"tcp","http-simple-new"),array(7100,"udp","Servidor de Fuentes X11"),array(8000,"tcp","iRDMI"),array(8080,"tcp","HTTP puerto 80. Tomcat lo usa como puerto por defecto."),array(8082,"tcp","blackice-alerts"),array(8118,"tcp","privoxy"),array(8443,"tcp","https"),array(8181,"tcp","https-simple-new"),array(8888,"tcp","sun-answerbook"),array(9000,"tcp","http-check"),array(9009,"tcp","Pichat peer-to-peer chat server"),array(9443,"tcp","https"),array(9898,"tcp","Gusano Dabber (troyano/virus)"),array(10000,"tcp","Webmin (Administración remota web)"),array(10011,"tcp","Team Speak"),array(19226,"tcp","Panda Security Puerto de comunicaciones de Panda Agent."),array(12345,"tcp","NetBus en:NetBus (troyano/virus)"),array(25565,"tcp","Minecraft Puerto por defecto usado por servidores del juego."),array(30033,"tcp","Team Speak"),array(31337,"tcp","Back Orifice herramienta de administración remota (por lo general troyanos)"),array(37777,"tcp","dahua-dvr"),array(45003,"tcp","Calivent herramienta de administración remota SSH con análisis de paquetes."),array(49152,"tcp"," http-supermicro"));


  




		function ping2($host) {
                /* ICMP ping packet with a pre-calculated checksum */
                $package = "\x08\x00\x7d\x4b\x00\x00\x00\x00PingHost";
                $socket  = socket_create(AF_INET, SOCK_RAW, 1);
                socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, array('sec' => 1, 'usec' => 0));
                socket_connect($socket, $host, null);

                $ts = microtime(true);
                socket_send($socket, $package, strLen($package), 0);
                if(@socket_read($socket, 255))
                       { $result = microtime(true) - $ts;
                    	$result=$result+0.05;
						 $result=number_format($result,3);}
                else{    $result = false;}
                socket_close($socket);

				
                return $result;
        }



 


	#LIMITE DE TIEMPO PARA VERIFICAR SI UNPUERTO ESTA ABIERTO O CERRADO
	function tiempo_lim($var)
	{
		$this->tiempo=$var;		
		$this->ping=0;
	}




	#LIMITE DE TIEMPO PARA VERIFICAR SI UNPUERTO ESTA ABIERTO O CERRADO
	function fuerza_bruta($var="tcp")
	{
		if (strtolower($var)=="tcp" or strtolower($var)=="udp" or strtolower($var)=="ssl" or strtolower($var)=="tls")
		{
			$this->Apuertos=array(65536,strtolower($var));		
		}
		else
		{
			die("Problablemente introdujo un protocolo de trasporte no Valido\nProtocolos Soportados ->TCP, UDP, SSL, TLS\nUsted Introdujo -> $var");	
		}

		
	}






	#ESTA OPCION SERVIRA PARA EXTRAR LOS DOMINIOS QUE TIENE LA DIRECCION IPV4
	function rev_dns()
	{
		
	}






	#IP QUE SE UTILIZARA PARA VERIFICAR LOS PUERTOS ABIERTOS
	function ip($ip,$pro="tcp",$mostrar=0)
	{
		$ts = microtime(true);

	if($this->ping){if(($tim=$this->ping2($ip))){$this->tiempo=$tim;}else{echo "\nNo contesto el Ping la ip: $ip y el tiepo que se usara sera de: ".$this->tiempo."\n";}}
		      echo "\nPUERTO/Protocolo  STATUS   SERVICIO\n";
		



		if (($this->Apuertos[0]) != 65536) 
		{
			for ($i=0; $i < count($this->Apuertos); $i++) 
			{
				if(strtolower($pro)==$this->Apuertos[$i][1])
				{


					$fp =fsockopen($this->Apuertos[$i][1]."://".$ip, $this->Apuertos[$i][0], $err, $errn, $this->tiempo);
					if ($fp) 
					{
						
					    echo $this->Apuertos[$i][0]."/".$this->Apuertos[$i][1]."            Open   ".$this->Apuertos[$i][2]."\n";
					    fclose($fp);
					    unset($fp);
					}
					elseif($mostrar)
					{
						echo $this->Apuertos[$i][0]."/".$this->Apuertos[$i][1]."            Close\n";
					} 


					fclose($fp);
					unset($fp);
				}elseif (strtolower($pro)!="tcp" and strtolower($pro)!="udp" and strtolower($pro)!="ssl" and strtolower($pro)!="tls") 
				{
					die("Problablemente introdujo un protocolo de trasporte no Valido\nProtocolos Soportados ->TCP, UDP, SSL, TLS\nUsted Introdujo -> $pro");	
				}
			}
		}
		elseif($this->Apuertos[1] == "tcp")
		{
			echo "Fuerza Bruta TCP Activada";
			for ($i=1; $i < $this->Apuertos[0]; $i++) 
			{ 

				$fp =fsockopen($this->Apuertos[1]."://$ip", $i, $errno, $errstr, $this->tiempo);
				if ($fp) 
				{
				     echo $i."/".$this->Apuertos[1]."            Open   \n";
				    fclose($fp);
				    unset($fp);
				}
				else
				{
				
					if($mostrar){echo $i."/".$this->Apuertos[1]."            Close   \n";}
					fclose($fp);
					unset($fp);
					
				} 

				

			}


		}
		else
		{
						echo "Fuerza Bruta UDP Activada";
			for ($i=1; $i < $this->Apuertos[0]; $i++) 
			{ 
						
				$fp =fsockopen($this->Apuertos[1]."://$ip", $i, $errno, $errstr, $this->tiempo);
				if ($fp) 
				{
				     echo $i."/".$this->Apuertos[1]."            Open   \n";
				    fclose($fp);
				    unset($fp);
				}
				else
				{
				
					if($mostrar){echo $i."/".$this->Apuertos[1]."            Close   \n";}
					fclose($fp);
					unset($fp);
					
				} 

				

			}

		}

			 $result = microtime(true) - $ts;
			$result=number_format($result,3);


		echo "\n###### ESCANEO TERMINADO  IP: $ip tiempo de tolerancia: ".$this->tiempo."sg  Tiempo de escaneo : $result sg #########\n";

	}









	#SIRVE PARA ANALIZAR UNAS IP ESPESIFICAS
	function rango_ip($ip,$pro="tcp",$mostrar=0,$iniciar=1,$final=244)
	{
		

	$ip2=explode(".", $ip);
	foreach ($ip2 as $key => $value) {
		if ($value=="*") {
			$octeto=$key+1;
		}

	}

	switch ($octeto)
	{
		case 1:
				echo "\nPUERTO/Protocolo  STATUS   SERVICIO\n";
			for ($i=$iniciar; $i <= $final; $i++)
				{                   
					if($this->ping){if(($tim=$this->ping2($i.".".$ip2[1].".".$ip2[2].".".$ip2[3]))){$this->tiempo=$tim;}else{echo "\nNo contesto el Ping la ip: $ip y el tiepo que se usara sera de: ".$this->tiempo."\n";}}
					echo "\n##################################### ip: ".$i.".".$ip2[1].".".$ip2[2].".".$ip2[3]."Tiempo: ".$this->tiempo."sg\n";
					for($a=0; $a < count($this->Apuertos); $a++) 
					{ 
						if(strtolower($pro)==$this->Apuertos[$a][1])
						{

							$fp =fsockopen($this->Apuertos[$a][1]."://".$i.".".$ip2[1].".".$ip2[2].".".$ip2[3], $this->Apuertos[$a][0], $errno, $errstr, $this->tiempo);
							if ($fp) 
							{
							    echo $this->Apuertos[$a][0]."/".$this->Apuertos[$a][1]."            Open   ".$this->Apuertos[$a][2]."\n";
							    fclose($fp);
							    unset($fp);
							}
							else
							{
							
								if($mostrar){echo $this->Apuertos[$a][0]."/".$this->Apuertos[$a][1]."            Close\n";}
								fclose($fp);
								unset($fp);
								
							}

						}
							elseif (strtolower($pro)!="tcp" and strtolower($pro)!="udp" and strtolower($pro)!="ssl" and strtolower($pro)!="tls")
						{
						die("Problablemente introdujo un protocolo de trasporte no Valido\nProtocolos Soportados ->TCP, UDP, SSL, TLS\nUsted Introdujo -> $pro");	
						}

					}	 
					
				}

				echo "\n\nFINNNNNNN";



			break;
		case 2:
			  echo "\nPUERTO/Protocolo  STATUS   SERVICIO\n";
			for ($i=$iniciar; $i <= $final; $i++)
				{
					if($this->ping){if(($tim=$this->ping2($ip2[0].".".$i.".".$ip2[2].".".$ip2[3]))){$this->tiempo=$tim;}else{echo "\nNo contesto el Ping la ip: $ip y el tiepo que se usara sera de: ".$this->tiempo."\n";}}
					echo "\n#####################################"." ip: ".$ip2[0].".".$i.".".$ip2[2].".".$ip2[3]."Tiempo: ".$this->tiempo."sg\n";
					for($a=0; $a < count($this->Apuertos); $a++) 
					{ 
						if(strtolower($pro)==$this->Apuertos[$a][1])
						{

							$fp =fsockopen($this->Apuertos[$a][1]."://".$ip2[0].".".$i.".".$ip2[2].".".$ip2[3], $this->Apuertos[$a][0], $errno, $errstr, $this->tiempo);
							if ($fp) 
							{
							    echo $this->Apuertos[$a][0]."/".$this->Apuertos[$a][1]."            Open   ".$this->Apuertos[$a][2]."\n";
							    fclose($fp);
							    unset($fp);
							}
							else
							{
							
								if($mostrar){echo $this->Apuertos[$a][0]."/".$this->Apuertos[$a][1]."            Close\n";}
								fclose($fp);
								unset($fp);
								
							}

						}
							elseif (strtolower($pro)!="tcp" and strtolower($pro)!="udp" and strtolower($pro)!="ssl" and strtolower($pro)!="tls")
						{
						die("Problablemente introdujo un protocolo de trasporte no Valido\nProtocolos Soportados ->TCP, UDP, SSL, TLS\nUsted Introdujo -> $pro");	
						}

					}	 
					
				}

				echo "\n\nFINNNNNNN";







			break;
		case 3:
			      echo "\nPUERTO/Protocolo  STATUS   SERVICIO\n";
			for ($i=$iniciar; $i <= $final; $i++)
				{
					if($this->ping){if(($tim=$this->ping2($ip2[0].".".$ip2[1].".".$i.".".$ip2[3]))){$this->tiempo=$tim;}else{echo "\nNo contesto el Ping la ip: $ip y el tiepo que se usara sera de: ".$this->tiempo."\n";}}
					echo "\n#####################################"." ip: ".$ip2[0].".".$ip2[1].".".$i.".".$ip2[3]."Tiempo: ".$this->tiempo."sg\n";
					for($a=0; $a < count($this->Apuertos); $a++) 
					{ 
						if(strtolower($pro)==$this->Apuertos[$a][1])
						{

							$fp =fsockopen($this->Apuertos[$a][1]."://".$ip2[0].".".$ip2[1].".".$i.".".$ip2[3], $this->Apuertos[$a][0], $errno, $errstr, $this->tiempo);
							if ($fp) 
							{
							    echo $this->Apuertos[$a][0]."/".$this->Apuertos[$a][1]."            Open   ".$this->Apuertos[$a][2]."\n";
							    fclose($fp);
							    unset($fp);
							}
							else
							{
							
								if($mostrar){echo $this->Apuertos[$a][0]."/".$this->Apuertos[$a][1]."            Close\n";}
								fclose($fp);
								unset($fp);
								
							}

						}
							elseif (strtolower($pro)!="tcp" and strtolower($pro)!="udp" and strtolower($pro)!="ssl" and strtolower($pro)!="tls")
						{
						die("Problablemente introdujo un protocolo de trasporte no Valido\nProtocolos Soportados ->TCP, UDP, SSL, TLS\nUsted Introdujo -> $pro");	
						}

					}	 
					
				}

				echo "\n\nFINNNNNNN";


			break;
		case 4:

				      echo "\nPUERTO/Protocolo  STATUS   SERVICIO\n";
			for ($i=$iniciar; $i <= $final; $i++)
				{
					if($this->ping){if(($tim=$this->ping2($ip2[0].".".$ip2[1].".".$ip2[2].".".$i))){$this->tiempo=$tim;}else{echo "\nNo contesto el Ping la ip: $ip y el tiepo que se usara sera de: ".$this->tiempo."\n";}}
echo "\n#####################################"." ip: ".$ip2[0].".".$ip2[1].".".$ip2[2].".".$i." Tiempo: ".$this->tiempo."sg\n";
					for($a=0; $a < count($this->Apuertos); $a++) 
					{ 
						if(strtolower($pro)==$this->Apuertos[$a][1])
						{

							$fp =fsockopen($this->Apuertos[$a][1]."://".$ip2[0].".".$ip2[1].".".$ip2[2].".".$i, $this->Apuertos[$a][0], $errno, $errstr, $this->tiempo);
							if ($fp) 
							{
							    echo $this->Apuertos[$a][0]."/".$this->Apuertos[$a][1]."            Open   ".$this->Apuertos[$a][2]."\n";
							    fclose($fp);
							    unset($fp);
							}
							else
							{
							
								if($mostrar){echo $this->Apuertos[$a][0]."/".$this->Apuertos[$a][1]."            Close\n";}
								fclose($fp);
								unset($fp);
								
							}

						}
							elseif (strtolower($pro)!="tcp" and strtolower($pro)!="udp" and strtolower($pro)!="ssl" and strtolower($pro)!="tls")
						{
						die("Problablemente introdujo un protocolo de trasporte no Valido\nProtocolos Soportados ->TCP, UDP, SSL, TLS\nUsted Introdujo -> $pro");	
						}

					}	 
					
				}

				echo "\n\nFINNNNNNN";




			break;

		default:
			die("\nNo cuenta con la parte del octeto con su asterisco ejemplo: 192.168.*.10\nEstued puso: -> ".$ip."\n");
			
	}











	}








	#RANGO DE IPS QUE SE UTILIZARAN PARA VERIFICAR RANGO DE PUERTO O SOLO UN PUERTO
	function ips($ips,$pro="tcp",$mostrar=0)
	{
		

		if (($this->Apuertos[0]) != 65536) 
		{	
			for ($a=0; $a < count($ips); $a++) 
			{
					if($this->ping){if(($tim=$this->ping2($ips[$a]))){$this->tiempo=$tim;}else{echo "\nNo contesto el Ping la ip: $ip y el tiepo que se usara sera de: ".$this->tiempo."\n";}}
				echo "\n################ ip: ".$ips[$a]."  tiempo :".$this->tiempo."sg ############\n";
				echo "\nPUERTO/Protocolo  STATUS   SERVICIO\n";
				
				for ($i=0; $i < count($this->Apuertos); $i++) 
				{ 
					if(strtolower($pro)==$this->Apuertos[$i][1])
					{
						#echo $this->Apuertos[$i][0]."/".$this->Apuertos[$i][1]."\n";
						
						$fp =fsockopen($this->Apuertos[$i][1]."://".$ips[$a], $this->Apuertos[$i][0], $err, $errn, $this->tiempo);
						if ($fp) 
						{
						    echo $this->Apuertos[$i][0]."/".$this->Apuertos[$i][1]."            Open   ".$this->Apuertos[$i][2]."\n";
						    fclose($fp);
						    unset($fp);
						}
						else
						{
					
							if($mostrar){echo $this->Apuertos[$i][0]."/".$this->Apuertos[$i][1]."            Close   \n";}
							fclose($fp);
							unset($fp);
							
						} 
					}
					elseif (strtolower($pro)!="tcp" and strtolower($pro)!="udp" and strtolower($pro)!="ssl" and strtolower($pro)!="tls") 
					{
						die("Problablemente introdujo un protocolo de trasporte no Valido\nProtocolos Soportados ->TCP, UDP, SSL, TLS\nUsted Introdujo -> $pro");	
					}
				}

			}
		}
		elseif($this->Apuertos[1] == "tcp")
		{
			echo "Fuerza Bruta TCP Activada";
			for ($a=0; $a < count($ips); $a++) 
			{
				if($this->ping){if(($tim=$this->ping2($ips[$a]))){$this->tiempo=$tim;}else{echo "\nNo contesto el Ping la ip: $ip y el tiepo que se usara sera de: ".$this->tiempo."\n";}}
				echo "\n################ ip: ".$ips[$a]."  tiempo :".$this->tiempo."sg ############\n";
				echo "\nPUERTO/Protocolo  STATUS   SERVICIO\n";
				for ($i=0; $i < $this->Apuertos[0]; $i++) 
				{ 
					
					$fp =fsockopen($this->Apuertos[1]."://".$ips[$a], $i, $errno, $errstr, $this->tiempo);
					if ($fp) 
					{
					    echo $i."/".$this->Apuertos[1]."            Open   \n";
					    fclose($fp);
					    unset($fp);
					}
					else
					{
				
						if($mostrar){echo $i."/".$this->Apuertos[1]."            Close   \n";}
						fclose($fp);
						unset($fp);
						
					} 

				}

			}

		}
		else
		{
						echo "Fuerza Bruta UDP Activada";
		
			for ($a=0; $a < count($ips); $a++) 
			{

				if($this->ping){if(($tim=$this->ping2($ips[$a]))){$this->tiempo=$tim;}else{echo "\nNo contesto el Ping la ip: $ip y el tiepo que se usara sera de: ".$this->tiempo."\n";}}

				echo "\n################ ip: ".$ips[$a]."  tiempo :".$this->tiempo."sg ############\n";
				echo "\nPUERTO/Protocolo  STATUS   SERVICIO\n";
				for ($i=0; $i < $this->Apuertos[0]; $i++) 
				{ 
					
					$fp =fsockopen($this->Apuertos[1]."://".$ips[$a], $i, $errno, $errstr, $this->tiempo);
					if ($fp) 
					{
					    echo $i."/".$this->Apuertos[1]."            Open   \n";
					    fclose($fp);
					    unset($fp);
					}
					else
					{
				
						if($mostrar){echo $i."/".$this->Apuertos[1]."            Close   \n";}
						fclose($fp);
						unset($fp);
						
					} 

				}

			}

		}
		echo "\n######### ESCANEO TERMINADO  ###########\n";


	}








	#RANGO DE PUERTOS QUE SE UTILIZARAN PARA VERIFICAR SI ESTAN AVIERTOS
	function puertos($var)
	{
		$this->Apuertos=$var;
	}






	#SE OBTENDRA LA INFORMACION DETALLADA DEL PUERTO QUE SE CONECTA
	function info()
	{
		
	}




	#SE OBTENDRA EL BANNER GRABING DE CADA PUERTO
	function banner()
	{
		
	}




	#SE OBTENDRA EL BANNER GRABING DE CADA PUERTO
	function geo($var)
	{
		//#Geolocalizacion ip: http://ip-api.com/#46.46.146.85
		#http://ip-api.com/php/83.242.170.130
		
	}






}


# ---------- futuras Versiones
#$port->cabeceras();  // este funcionaria para mandar peticiones a cerbidores http o cualquier otro servidore que nesesite cabeceras
#$port->conectarse_al_sericio_y_regresar_su_banner_grabing
#$port->guardardb();
#$port->rev_dns();      //reversa dns con bing dando todos los nombres de dominios
#$port->info();
#$port->banner();




$port= new portscan();

#$port->rango_ip("200.0.0.*",1,255)   // ip a escanear  ips("192.168.1.0" , numero de opteto, empezar-1 , terminar-255);







#$port->tiempo_lim(0.5);
$port->fuerza_bruta("tcp");

#$port->puertos(array(array(80,"tcp","http"),array(443,"tcp","http"),array(554,"tcp","http"),array(3702,"tcp","http"),array(8080,"tcp","http"),array(9000,"tcp","http"),array(500,"tcp","http"),array(49152,"tcp","http"),array(4500,"tcp","http")));

#-187.216.68.146
#$port->ips(array("136.0.111.50","67.149.234.238"),"tcp",1);


$port->ip(/*IP Scanear*/"www.google.com", /* Protocolo*/ "tcp", /*0 solo para mostrar los puertos abiertos y 1 para mostrar todo*/0);    


#$port->ip("1.1.1.1","tcp",0);
#$port->puertos(array(array(5900,"tcp","REAL-VNC"),array(5901,"tcp","REAL-VNC"),array(554,"tcp","RSTP"),array(6000,"tcp","X11")));
#$port->rango_ip("201.156.12.*","tcp",0,1,254);    #rango_ip("136.0.111.*","tcp",para_mostrar los puertos abieros o cerrados,rango inicial, rango final)





?>
