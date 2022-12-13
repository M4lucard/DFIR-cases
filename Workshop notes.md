**Getting the Follina trigger ready:**

Head over to our Kali box and open up a terminal

Now **cd** in to the Follina/**msdt-follina** directory on the desktop

Now let's run the python script using this command.

**_python3 follina.py_**

**![](https://files.cdn.thinkific.com/file_uploads/337008/images/c7e/7eb/64b/1654105708992.jpg)
Now there should be a Microsoft Word document inside of our **msdt-folina** directory.

We need to copy over the file from our Kali box to our Windows machine, to do that we will first need to enable networking in VirtualBox to allow connectivity. 

First click on **file** and then **preferences** 

![](https://files.cdn.thinkific.com/file_uploads/337008/images/b3d/59f/cd8/1654105980342.jpg)

![](https://files.cdn.thinkific.com/file_uploads/337008/images/a95/cd2/e9b/1654106010376.jpg)

Then click on **Network** and then select the green **+** on the right side to create a new network

![](https://files.cdn.thinkific.com/file_uploads/337008/images/df8/952/762/1654106060626.jpg)

If you want to name the network you can double click on the network and change the name. 

![](https://files.cdn.thinkific.com/file_uploads/337008/images/5ab/59c/b8b/1654106099993.jpg)

Now we need to change the network settings for both of our VMs, select your VM and then click on **Settings,** navigate to **Network** and change your Attached network to be **NAT Network** then under the advanced settings, set the **Promiscuous Mode** to **Allow All.**

![](https://files.cdn.thinkific.com/file_uploads/337008/images/799/1e0/b97/1654106156463.jpg)

![](https://files.cdn.thinkific.com/file_uploads/337008/images/9e8/48a/918/1654106213763.jpg)

Once this is done, go back to our Linux box and navigate to the **mdst-folina** in a new terminal and run these commands.

Grab the IP of the Kali box

**_ip address_**

Start HTTP server

**_python3 -m http.server 8080_**

Now hop back on the Windows box and get on the browser and navigate to http://<Kali-ip>:8080

You should be presented with the msdt directory and you can now download the **follina.doc** file

![](https://files.cdn.thinkific.com/file_uploads/337008/images/256/313/961/1654106828412.jpg)

**Testing the vulnerability:**

Now head back to your Kali box and go to our original terminal where our follina script is running

Once you have that back up, go to where you downloaded the **follina.doc** file and launch it!

Accept all of the agreements and then hit **Enable Editing** at the top.

Now if you did this correctly, you should get an notification from Windows Defender that this was blocked. If you didn't do this correctly, delete the **follina.doc** file on linux and windows and rerun the **follina.py** script and repeat the process of using the http server to get the doc file over to your Windows machine. 

  

To get Windows Defender to ignore this, go to your **Virus & threat protection settings** and turn off **Real-time protection(DO NOT DISABLE THIS ON A COMPUTER THAT YOU ARE NOT OKAY WITH DESTROYING)**

![](https://files.cdn.thinkific.com/file_uploads/337008/images/bc7/75f/9c6/1654107478387.jpg)

![](https://files.cdn.thinkific.com/file_uploads/337008/images/df4/5ef/58d/1654107456217.jpg)

Now you should be able to run this script without interruption from pesky anti virus tools!

If you open the doc again after disabling Windows Defender you should see this!

![](https://files.cdn.thinkific.com/file_uploads/337008/images/9e1/70d/ecd/1654107620006.jpg)

Keep playing around with the options and see what you can do!