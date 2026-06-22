import dictquery

cmd = {"CommandLine": " -EncodedCommand "}
print(dictquery.match(cmd, "CommandLine LIKE '* -encodedcommand *'"))
