<?php
/*
 *
 * JetCSFManager @ whmcs module package
 * Created By Idan Ben-Ezra
 *
 * Copyrights @ Jetserver Web Hosting
 * http://jetserver.net
 *
 **/

use WHMCS\Database\Capsule;

if (!defined("JETCSFMANAGER"))
	die("This file cannot be accessed directly");

class jcsf_firewall_default
{
	public function _default()
	{	
		global $instance, $cc_encryption_hash;
		
		$output = array('success' => true, 'message' => '', 'data' => array());
		
		$instance = csfmanager::getInstance();
		
		$output['data']['servers'] = array();
		
        $builder = Capsule::table('tblservers');

        if (trim($instance->getConfig('servers', ''))) {
            $builder->whereIn('id', trim($instance->getConfig('servers', '')));
        }

        $result = $builder->get();

        $resultAsArray = json_decode(json_encode($result), true);

		foreach ($resultAsArray as $server_details) {
			$output['data']['servers'][$server_details['id']] = array_merge($server_details, array('password' => decrypt($server_details['password'], $cc_encryption_hash)));
		}

		return $output;
	}
}

?>