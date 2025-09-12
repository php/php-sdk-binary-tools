<?php

/*
	- go through all zip files in the given dirs non recursively
	- read all the lib filenames from those zips
	- create mappings between lib filename and zip filename

	Usage:
	php libmap.php [--pretty] path0 [ path1 ... ] > libmapping.json
*/


/*$dirs = array(
	"C:\\tmp\\core_deps\\vc9\\x86",
	"C:\\tmp\\core_deps\\vc11\\x86",
	"C:\\tmp\\core_deps\\vc11\\x64",
);*/

/*$dirs = array(
	"C:\\tmp\\libs",
);*/

$sopt = "p";
$lopt = array(
	"pretty",
);

$flags = 0;
$opt = getopt($sopt, $lopt);
foreach ($opt as $name => $val) {
	switch ($name) {
		case "p":
		case "pretty":
			$flags = JSON_PRETTY_PRINT;
			break;
	}
}


$dirs = array();
foreach (array_slice($_SERVER["argv"], (0 == $flags ? 1 : 2)) as $item) {
	if (file_exists($item) && is_dir($item)) {
		$dirs[] = $item;
	}
}

if (empty($dirs)) {
	echo "Nothing to do\n";
	die;
}

$out = array();

foreach ($dirs as $path) {
	$dir = new DirectoryIterator($path);
	foreach ($dir as $fileinfo) {
		if ($fileinfo->isDot() || $fileinfo->isDir()) {
			continue;
		}

		$pathname = $fileinfo->getPathname();
		$filename = $fileinfo->getFilename();

		if (substr($filename, -3) != "zip") {
			continue;
		}

		if (!preg_match(",.*-(v[c|s]\d+)-(x\d\d)\.zip,", $filename, $m)) {
			continue;
		}

		$crt = $m[1];
		$arch = $m[2];

		if (!isset($out[$crt])) {
			$out[$crt] = array();
		}
		if (!isset($out[$crt][$arch])) {
			$out[$crt][$arch] = array();
		}

		$zip = new ZipArchive();

		$zip->open($pathname);

		$libs = array();

		for ($i = 0; $i < $zip->numFiles; $i++) {
			$stat = $zip->statIndex($i);

			if (substr($stat['name'], -3) != "lib") {
				continue;
			}

			$libs[] = basename($stat['name']);
		}

		$zip->close();
		unset($zip);


		if (!empty($libs)) {
			$out[$crt][$arch][$filename] = $libs;
		}
	}
}

echo json_encode($out, $flags);

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */