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

class jcsf_allowedlog_default
{
    public function _default()
    {
        global $cc_encryption_hash, $instance;

        $output = array('success' => true, 'message' => '', 'data' => array());

        $instance = csfmanager::getInstance();

        $id = csfmanager::request_var('id', 0);
        $start = csfmanager::request_var('start', 0);
        $search = csfmanager::request_var('search', array());

        $limit = 10;

        $output['data']['search_url'] = sizeof($search) ? http_build_query($search) : '';

        $output['data']['list'] = array();

        $builder = Capsule::table('mod_csfmanager_allow as a');
        $builder->select('a.*', 'c.firstname', 'c.lastname', 's.name as server_name');
        $builder->leftJoin('tblclients as c', 'c.id', '=', 'a.clientid');
        $builder->leftJoin('tblservers as s', 's.id', '=', 'a.serverid');
        $builder->where('a.expiration', '>', time());

        if (trim($search['clientname'])) {
            $builder->where(Capsule::raw('UPPER(CONCAT_WS(\' \', c.firstname, c.lastname))'), 'LIKE', '%' . trim($search['clientname']) . '%');
        }

        if (intval($search['server'])) {
            $builder->where('s.id', '=', intval($search['server']));
        }

        if (trim($search['ip'])) {
            $builder->where('a.ip', 'LIKE', '%' . trim($search['ip']) . '%');
        }

        if (trim($search['reason'])) {
            $builder->where('a.reason', 'LIKE', '%' . trim($search['reason']) . '%');
        }

        $builder->orderBy('a.time', 'DESC');

        $output['data']['total'] = $builder->count();

        $builder->offset($start)->limit($limit);

        $result = $builder->get();

        $resultAsArray = json_decode(json_encode($result), true);

        foreach ($resultAsArray as $allow_details) {
            $output['data']['list'][] = array_merge($allow_details, array('time' => date("d/m/Y H:i", $allow_details['time']), 'expiration' => date("d/m/Y H:i", $allow_details['expiration'])));
        }

        $output['data']['current_page'] = (($start / $limit) + 1);
        $output['data']['total_pages'] = ceil(abs($output['data']['total'] / $limit));
        $output['data']['search'] = $search;
        $output['data']['start'] = $start;
        $output['data']['limit'] = $limit;

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

    public function delete()
    {
        global $cc_encryption_hash;

        $output = array('success' => false, 'message' => '', 'data' => array());

        $instance = csfmanager::getInstance();

        $id = csfmanager::request_var('id', 0);

        $builder = Capsule::table('mod_csfmanager_allow as a')
            ->select('a.ip', 's.id as server_id', 's.name', 's.hostname', 's.username', 's.password', 's.accesshash', 's.secure')
            ->leftJoin('tblservers as s', 's.id', '=', $id)
            ->where('a.id', '=', $id);

        $result = $builder->get();

        $allow_details = json_decode(json_encode($result), true);

        if (!$allow_details) {
            $output['message'] = $instance->lang('ipnotexists');
            return $output;
        }

        $allow_details['password'] = decrypt($allow_details['password'], $cc_encryption_hash);

        $Firewall = new Firewall($LANG);
        $Firewall->setWHMdetails($allow_details);

        // delete this ip
        if (!$Firewall->setIP($allow_details['ip'])) {
            $output['message'] = $instance->lang('cantsetip');
            return $output;
        }

        if (!$Firewall->quickUnblock()) {
            $output['message'] = $instance->lang('cantremoveip');
            return $output;
        }

        Capsule::table('mod_csfmanager_allow')->where('id', '=', $id)->delete();

        $output['success'] = true;
        $output['message'] = $instance->lang('allowedipremove');

        return $output;
    }
}

?>