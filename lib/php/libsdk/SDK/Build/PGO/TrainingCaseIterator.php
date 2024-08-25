<?php

namespace SDK\Build\PGO;

use SDK\Build\PGO\Config as PGOConfig;

/**
 * @implements \Iterator<?string,Interfaces\TrainingCase>
 */
class TrainingCaseIterator implements \Iterator
{
	/** @var PGOConfig */
	protected $conf;

	/** @var array<string> */
	protected $items = array();

	/** @var int */
	protected $idx;

	/** @var object */
	protected $el;

	public function __construct(PGOConfig $conf)
	{
		$this->rewind();

		$this->conf = $conf;

		$items = glob($this->conf->getCasesTplDir() . DIRECTORY_SEPARATOR . "*");
		foreach ($items as $it) {
			if (!is_dir($it)) {
				continue;
			}

			if (!file_exists($this->getHandlerFilename($it))) {
				echo "Test case handler isn't present in '$it'.\n";
				continue;
			}

			if ($this->isInactive($it)) {
				echo "The test case in '$it' is marked inactive.\n";
				continue;
			}

			$this->items[] = $it;
		}


	}

	protected function isInactive(string $base) : bool
	{
		return file_exists($base . DIRECTORY_SEPARATOR . "inactive");
	}

	protected function getHandlerFilename(string $base) : string
	{
		return $base . DIRECTORY_SEPARATOR . "TrainingCaseHandler.php";
	}

	#[\ReturnTypeWillChange]
	public function current()
	{
		$base = $this->items[$this->idx];
		$ns = basename($base);

		/* Don't overwrite generated config. */
		$it = $this->conf->getSectionItem($ns);
		if (!$it) {
			$this->conf->importSectionFromDir($ns, $base);
		}

		require_once $this->getHandlerFilename($base);

		$srv_http = $this->conf->getSrv($this->conf->getSectionItem($ns, "srv_http"));
		$srv_db = $this->conf->getSrv($this->conf->getSectionItem($ns, "srv_db"));

		$class = "$ns\\TrainingCaseHandler";

		$this->el = new $class($this->conf, $srv_http, $srv_db);

		return $this->el;
	}

	#[\ReturnTypeWillChange]
	public function next()
	{
		$this->idx++;
	}

	#[\ReturnTypeWillChange]
	public function rewind()
	{
		$this->idx = 0;
	}

	#[\ReturnTypeWillChange]
	public function valid()
	{
		return $this->idx < count($this->items);
	}

	#[\ReturnTypeWillChange]
	public function key()
	{
		if (!is_object($this->el)) {
			return NULL;
		}

		return $this->el->getName();
	}
}
