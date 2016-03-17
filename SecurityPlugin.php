<?php

/**
 * @author      Quentin Ligier
 * @copyright   2016 by Quentin Ligier
 * @description Add an extra layer of security to Lychee
 */

namespace Security;

if (!defined('LYCHEE'))
	exit('Error: Direct access is not allowed!');


class SecurityPlugin implements \SplObserver {

	# Array of IPs to whitelist; they will never be blocked
	private $whitelistIps = array();

	# Array of IPs to blacklist; they won't be able to access the website
	private $blacklistIps = array();

	# Maximum number of login attempts; set to false to deactivate
	private $maxNumberOfAttempts = 3;

	# Time (in seconds) during which attempts are counted
	private $resetAttemptTime = 600;

	# Don't modify following variables
	private $_userWhitelisted = false;
	private $_pregLogText = '/User \[([^\]]+)\] has tried to log in from \[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/U';



	public function __construct() {
		if (in_array($_SERVER['REMOTE_ADDR'], $this->blacklistIps))
			$this->denyAccess();

		if (in_array($_SERVER['REMOTE_ADDR'], $this->whitelistIps))
			$this->_userWhitelisted = true;
	}

	public function update(\SplSubject $subject) {
		if ('Lychee\\Modules\\Session::login:before' === $subject->action)
			$this->checkLoginAuth();
	}

	private function checkLoginAuth() {
		if ($this->_userWhitelisted)
			return;

		# Login attempts check deactivated
		if (false === $this->maxNumberOfAttempts || 1 > $this->maxNumberOfAttempts)
			return;


		# Count the number of failed attempts per IP
		$oldestAttemptTime = time() - $this->resetAttemptTime;
		$query = \Lychee\Modules\Database::prepare(\Lychee\Modules\Database::get(), "SELECT text FROM ? WHERE time > ?", array(LYCHEE_TABLE_LOG, $oldestAttemptTime));
		$result = \Lychee\Modules\Database::get()->query($query);
		if (false === $result)
			return;

		$loggedAttempts = array();
		$pregMatch = array();
		while ($row = $result->fetch_object()) {
			error_log('SecuPlugin: checkLoginAuth -> '.$row->text, 0);
			if (preg_match($this->_pregLogText, $row->text, $pregMatch) === 1) {
				$ip =& $pregMatch[2];

				if (!isset($loggedAttempts[$ip]))
					$loggedAttempts[$ip] = 0;
				++$loggedAttempts[$ip];
			}
		}


		# Check for the login tries
		if (isset($loggedAttempts[$_SERVER['REMOTE_ADDR']]) && $loggedAttempts[$_SERVER['REMOTE_ADDR']] >= $this->maxNumberOfAttempts)
			$this->denyAccess();
	}

	private function denyAccess() {
		header('HTTP/1.0 403 Forbidden');
		echo 'You are forbidden!';
		die;
	}

	private function purgeOldLogs() {

	}

}