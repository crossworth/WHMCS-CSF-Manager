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

class jcsf_generatekey_default
{
	public function _default()
	{	
		global $cc_encryption_hash, $instance;
		
		$output = array('success' => true, 'message' => '', 'data' => array());

		$instance = csfmanager::getInstance();
		
		$output['data']['generate'] = csfmanager::request_var('generate', array());
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

		$output['data']['clients'] = array();

        $builder = Capsule::table('tblclients as c')
            ->join('tblhosting as h', 'h.userid', '=', 'c.id')
            ->join('tblproducts as p', 'p.id', '=', 'h.packageid')
            ->join('tblservers as s', 's.id', '=', 'h.server')
            ->where('c.status', '=', 'Active');

        if (trim($instance->getConfig('servers', ''))) {
            $builder->whereIn('s.id', trim($instance->getConfig('servers', '')));
        }

        $builder->whereIn('p.type', ['hostingaccount', 'reselleraccount', 'server'])
            ->orderBy('c.firstname', 'ASC')
            ->orderBy('c.lastname', 'ASC')
            ->orderBy('c.id', 'ASC');

        $result = $builder->get();

        $resultAsArray = json_decode(json_encode($result), true);

        foreach ($resultAsArray as $client_details) {
            $output['data']['clients'][$client_details['id']] = $client_details;
        }

		return $output;
	}

	public function create()
	{	
		global $cc_encryption_hash, $instance, $CONFIG;
        $uid = intval($_SESSION['uid']);
		
		$output = $this->_default();
		if(!$output['success']) return $output;
		$output['success'] = false;

		$instance = csfmanager::getInstance();

		$client_id = intval($output['data']['generate']['clientid']) ? intval($output['data']['generate']['clientid']) : intval($output['data']['generate']['client']);

		if($output['data']['generate']['recipient'] && $output['data']['generate']['email'] && csfmanager::csfValidateEmail($output['data']['generate']['email']) && $client_id && isset($output['data']['clients'][$client_id]) && intval($output['data']['generate']['server']) && isset($output['data']['servers'][$output['data']['generate']['server']]))
		{
			$hashkey = md5($output['data']['generate']['email'] . rand() . time());
			$sysurl = ($CONFIG["SystemSSLURL"] ? $CONFIG["SystemSSLURL"] : $CONFIG["SystemURL"]);
			$whitelist_url = "{$sysurl}/index.php?m=csfmanager&action=allow&key={$hashkey}";
			$cancel_url = "{$sysurl}/index.php?m=csfmanager&action=cancel&key={$hashkey}";
			$valid_days = 365;
			$valid_clicks = 10;
	
			$sendmail = csfmanager::sendCSFmail('CSF Manager Whitelist by Email', $output['data']['generate']['email'], $output['data']['generate']['recipient'], array(
				'emailfullname'		=> $output['data']['generate']['recipient'],
				'firstname'		=> $output['data']['clients'][$client_id]['firstname'],
				'lastname'		=> $output['data']['clients'][$client_id]['lastname'],
				'whitelist_url'		=> $whitelist_url,
				'valid_days'		=> $valid_days,
				'valid_clicks'		=> $valid_clicks,
				'cancel_url'		=> $cancel_url,
				'signature'		=> nl2br(html_entity_decode($CONFIG['Signature'])),
			));
	
			if($sendmail['success'])
			{
				logActivity("Jetserver CSF Manager :: The admin sent allow ket to the recipient {$output['data']['generate']['email']} ({$output['data']['generate']['recipient']}) on behalf of <a href=\"clientssummary.php?userid={$uid}\">Client ID: {$uid}</a>");
	
                Capsule::table('mod_csfmanager_allow_keys')->insert(
                    [
                        'user_id' => $client_id,
                        'server_id' => $output['data']['clients'][$client_id]['server_id'],
                        'product_id' => $output['data']['clients'][$client_id]['hosting_id'],
                        'key_hash' => $hashkey,
                        'key_recipient' => $output['data']['generate']['recipient'],
                        'key_email' => $output['data']['generate']['email'],
                        'key_clicks_remained' => $valid_clicks,
                        'key_expire' => (time() + (60 * 60 * 24 * $valid_days)),
                    ]
                );
	
				$output['success'] = true;
				$output['message'] = $instance->lang('emailsent');
			}
			else
			{
				$output['errormessages'][] = $sendmail['message'];
			}
		}
		else
		{
			if(!$output['data']['generate']['recipient']) $output['errormessages'][] = $instance->lang('emptyrecipientname');
			if(!$output['data']['generate']['email']) $output['errormessages'][] = $instance->lang('emptyrecipientemail');
			if($output['data']['generate']['email'] && !csfmanager::csfValidateEmail($output['data']['generate']['email'])) $output['errormessages'][] = $instance->lang('invalidrecipientemail');
			if(!$client_id) $output['errormessages'][] = $instance->lang('emptyclient');
			if($client_id && !isset($output['data']['clients'][$client_id])) $output['errormessages'][] = $instance->lang('invalidclient');
			if(!intval($output['data']['generate']['server'])) $output['errormessages'][] = $instance->lang('emptyserver');
			if(intval($output['data']['generate']['server']) && !isset($output['data']['servers'][$output['data']['generate']['server']])) $output['errormessages'][] = $instance->lang('invalidserver');
		}
			
		return $output;
	}
}

?>