<?php

namespace SDK\Build\PGO\Abstracts;

use SDK\Build\PGO\Interfaces;

abstract class Server
{
	protected $name;
	protected $php;

	public function getName() : string
	{
		return $this->name;
	}

	public function getPhp() : Interfaces\PHP
	{
		return $this->php;
	}

}
