<?php
if(isset($_FILES['file'])){
    $errors= array();
    $file_name = $_FILES['file']['name'];
    $file_tmp =$_FILES['file']['tmp_name'];
    
    // Filtro básico (solo para hacerlo interesante)
    if(preg_match("/\.php$/", $file_name)){
        echo "Error: PHP files are not allowed!";
    } else {
        move_uploaded_file($file_tmp,"uploads/".$file_name);
        echo "Success! File uploaded to uploads/".$file_name;
    }
}
?>
<html>
   <body>
      <form action="" method="POST" enctype="multipart/form-data" id="upload_lab">
         <input type="file" name="file" />
         <input type="submit"/>
      </form>
   </body>
</html>
