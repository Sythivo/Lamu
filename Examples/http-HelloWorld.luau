local http = import 'http';
local server = http.new();

server:Get('/', function(request, response)
	print('[Get Request]');
	response:send([[
<!DOCTYPE html>
<html>
	<body>

	<h1>Hello World!</h1>

	</body>
</html>
]], "text/html");
end);

task.delay(0.5, function()
	print("from thread #1");
end);
task.spawn(function()
	print("from thread #2");
end);

server:listen("127.0.0.1", 3000);