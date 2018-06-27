$scriptToExecute = 
{
get-service
}
$b = Invoke-Command -ScriptBlock $scriptToExecute -ComputerName lanmbwapp014 4>&1
$b