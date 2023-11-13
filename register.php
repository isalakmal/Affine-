<?php
# Include connection
require_once "./config.php";

# Fungsi untuk mengenkripsi kata sandi dengan Vigenere Cipher
function affineEncrypt($plaintext, $a, $b) {
  $m = 26; // Ukuran alfabet (asumsi huruf kecil)
  $encryptedText = '';

  for ($i = 0; $i < strlen($plaintext); $i++) {
      $char = $plaintext[$i];
      if (ctype_lower($char)) {
          $x = ord($char) - ord('a');
          $encryptedChar = ($a * $x + $b) % $m;
          $encryptedText .= chr($encryptedChar + ord('a'));
      } else {
          $encryptedText .= $char; // Biarkan karakter non-alfabet seperti apa adanya
      }
  }

  return $encryptedText;
}

function modInverse($a, $m) {
  for ($x = 1; $x < $m; $x++) {
      if (($a * $x) % $m == 1) {
          return $x;
      }
  }
  return -1; // Invers tidak ada
}

# Key untuk Affine Cipher
$a = 5;  // Nilai 'a' (pastikan coprime dengan 26)
$b = 7;  // Nilai 'b'

# Define variables and initialize with empty values
$username_err = $email_err = $password_err = "";
$username = $email = $password = "";

# Processing form data when form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
  # Validate username
  if (empty(trim($_POST["username"]))) {
    $username_err = "Silahkan Masukkan Username";
  } else {
    $username = trim($_POST["username"]);
    if (!ctype_alnum(str_replace(array("@", "-", "_"), "", $username))) {
      $username_err = "Username Hanya Bisa Huruf dan Angka, Tidak Bisa Simbol Seperti '@', '_', or '-'.";
    } else {
      # Prepare a select statement
      $sql = "SELECT id FROM users WHERE username = ?";

      if ($stmt = mysqli_prepare($link, $sql)) {
        # Bind variables to the statement as parameters
        mysqli_stmt_bind_param($stmt, "s", $param_username);

        # Set parameters
        $param_username = $username;

        # Execute the prepared statement 
        if (mysqli_stmt_execute($stmt)) {
          # Store result
          mysqli_stmt_store_result($stmt);

          # Check if username is already registered
          if (mysqli_stmt_num_rows($stmt) == 1) {
            $username_err = "Username Sudah Terdaftar";
          }
        } else {
          echo "<script>" . "alert('Oops! Something went wrong. Please try again later.')" . "</script>";
        }

        # Close statement 
        mysqli_stmt_close($stmt);
      }
    }
  }

  # Validate email 
  if (empty(trim($_POST["email"]))) {
    $email_err = "Silahkan Masukkan Email";
  } else {
    $email = filter_var($_POST["email"], FILTER_SANITIZE_EMAIL);
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
      $email_err = "Masukkan Email yang Terdaftar";
    } else {
      # Prepare a select statement
      $sql = "SELECT id FROM users WHERE email = ?";

      if ($stmt = mysqli_prepare($link, $sql)) {
        # Bind variables to the statement as parameters
        mysqli_stmt_bind_param($stmt, "s", $param_email);

        # Set parameters
        $param_email = $email;

        # Execute the prepared statement 
        if (mysqli_stmt_execute($stmt)) {
          # Store result
          mysqli_stmt_store_result($stmt);

          # Check if email is already registered
          if (mysqli_stmt_num_rows($stmt) == 1) {
            $email_err = "Email Sudah Terdaftar";
          }
        } else {
          echo "<script>" . "Terjadi Kesalahan, Silahkan Coba Lagi');" . "</script>";
        }

        # Close statement
        mysqli_stmt_close($stmt);
      }
    }
  }

  # Validate password
  if (empty(trim($_POST["password"]))) {
    $password_err = "Masukkan Password";
  } else {
    $password = trim($_POST["password"]);
    if (strlen($password) < 8) {
      $password_err = "Password Harus 8 Karakter atau Lebih";
    }
  }

  # Check input errors before inserting data into database
  if (empty($username_err) && empty($email_err) && empty($password_err)) {
    $param_password = affineEncrypt($password, $a, $b);
    # Prepare an insert statement
    $sql = "INSERT INTO users(username, email, password) VALUES (?, ?, ?)";

    if ($stmt = mysqli_prepare($link, $sql)) {
      # Bind varibales to the prepared statement as parameters
      mysqli_stmt_bind_param($stmt, "sss", $param_username, $param_email, $param_password);

      # Set parameters
      $param_username = $username;
      $param_email = $email;
      $param_password = affineEncrypt($password, $a, $b);


      # Execute the prepared statement
      if (mysqli_stmt_execute($stmt)) {
        echo "<script>" . "Pendaftaran berhasil diselesaikan. Login untuk melanjutkan');" . "</script>";
        echo "<script>" . "window.location.href='./login.php';" . "</script>";
        exit;
      } else {
        echo "<script>" . "Terjadi Kesalahan, Silahkan Coba Lagi');" . "</script>";
      }

      # Close statement
      mysqli_stmt_close($stmt);
    }
  }

  # Close connection
  mysqli_close($link);
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>User login system</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.0-beta1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-0evHe/X+R7YkIZDRvuzKMRqM+OrBnVFBL6DOitfPri4tjfHxaWutUpFmBp4vmVor" crossorigin="anonymous">
  <link rel="stylesheet" href="./css/main.css">
  <link rel="shortcut icon" href="./img/favicon-16x16.png" type="image/x-icon">
  <script defer src="./js/script.js"></script>
</head>

<body>
  <div class="container">
    <div class="row min-vh-100 justify-content-center align-items-center">
      <div class="col-lg-5">
        <div class="form-wrap border rounded p-4">
          <h1>Daftar</h1>
          <p>Silahkan Isi Form Register</p>
          <!-- form starts here -->
          <form action="<?= htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" novalidate>
            <div class="mb-3">
              <label for="username" class="form-label">Username</label>
              <input type="text" class="form-control" name="username" id="username" value="<?= $username; ?>">
              <small class="text-danger"><?= $username_err; ?></small>
            </div>
            <div class="mb-3">
              <label for="email" class="form-label">Email Address</label>
              <input type="email" class="form-control" name="email" id="email" value="<?= $email; ?>">
              <small class="text-danger"><?= $email_err; ?></small>
            </div>
            <div class="mb-2">
              <label for="password" class="form-label">Password</label>
              <input type="password" class="form-control" name="password" id="password" value="<?= $password; ?>">
              <small class="text-danger"><?= $password_err; ?></small>
            </div>
            <div class="mb-3 form-check">
              <input type="checkbox" class="form-check-input" id="togglePassword">
              <label for="togglePassword" class="form-check-label">Tampilkan Password</label>
            </div>
            <div class="mb-3">
              <input type="submit" class="btn btn-primary form-control" name="submit" value="Daftar">
            </div>
            <p class="mb-0">Sudah Punya Akun? <a href="./login.php">Log In</a></p>
          </form>
          <!-- form ends here -->
        </div>
      </div>
    </div>
  </div>
</body>

</html>