# Shell as a Service Version 1

https://arphost.com/index.php/store/whmcs-addons/shell-as-a-service

Shell commands run as a service in WHMCS

# For WHMCS 8.x
1. Extact shellasaservice-1.1.zip to shellaservice.
2. Upload shellasaservice to your addons (modules/addons) folder under modules in your whmcs directory.
3. Login to WHMCS and go to Syetm Settings -> Addon Modules and Active Shell as a Service.
4. Next Set Access controls, enter your license  and save changes.
5. Now you can setup a product or product addon with a shell script. Go to Product/Services. Add a new Product Group or use an existing. 
6. Create a new product. 
7. Go to the Modules settings tab of the product.
8. Select Shellasaservice from the Module Name dropdown. In createbash put the path to your shell script including the script. 
9. If you would like it to run after payment tick	Automatically setup the product as soon as the first payment is received

