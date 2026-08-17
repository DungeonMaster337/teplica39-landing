<?php
/**
 * Теплицы39 — панель управления фотографиями.
 * Один файл. Пишет content/photos.json и складывает картинки в img/.
 * Пароль задаётся при первом входе и хранится хешем в admin/passwd.php
 * (файл с расширением .php — при прямом обращении отдаёт пустоту, а не хеш).
 */
declare(strict_types=1);

const ROOT      = __DIR__ . '/..';
const JSON_PATH = ROOT . '/content/photos.json';
const IMG_DIR   = ROOT . '/img';
const PASS_FILE = __DIR__ . '/passwd.php';
const MAX_BYTES = 8 * 1024 * 1024;

const MODELS = [
    'hero'   => 'Главное фото (первый экран)',
    'beta'   => 'Бета',
    'sigma'  => 'Сигма',
    'prima3' => 'Прима 3',
    'prima4' => 'Прима 4',
    'yota'   => 'Йота',
];
// Разрешаем только то, что реально является картинкой. Расширение берём отсюда, не от пользователя.
const TYPES = [IMAGETYPE_JPEG => 'jpg', IMAGETYPE_PNG => 'png', IMAGETYPE_WEBP => 'webp'];

session_set_cookie_params(['httponly' => true, 'samesite' => 'Strict']);
session_start();

/* ---------------------------------------------------------------- helpers */

function h(?string $s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function stored_hash(): ?string
{
    if (!is_file(PASS_FILE)) {
        return null;
    }
    $hash = include PASS_FILE;
    return is_string($hash) && $hash !== '' ? $hash : null;
}

function csrf(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(16));
    }
    return $_SESSION['csrf'];
}

function check_csrf(): void
{
    $sent = (string) ($_POST['csrf'] ?? '');
    if (!hash_equals($_SESSION['csrf'] ?? '', $sent)) {
        throw new RuntimeException('Сессия устарела — обновите страницу и повторите.');
    }
}

function load_data(): array
{
    $data = is_file(JSON_PATH) ? json_decode((string) file_get_contents(JSON_PATH), true) : null;
    if (!is_array($data)) {
        $data = [];
    }
    $data['models']  = is_array($data['models'] ?? null) ? $data['models'] : [];
    $data['gallery'] = is_array($data['gallery'] ?? null) ? array_values($data['gallery']) : [];
    foreach (array_keys(MODELS) as $key) {
        $data['models'][$key] = is_string($data['models'][$key] ?? null) ? $data['models'][$key] : '';
    }
    return $data;
}

function save_data(array $data): void
{
    $dir = dirname(JSON_PATH);
    if (!is_dir($dir) && !@mkdir($dir, 0755, true)) {
        throw new RuntimeException('Нет папки content/ и не удалось её создать.');
    }
    $json = json_encode(
        ['models' => $data['models'], 'gallery' => array_values($data['gallery'])],
        JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );
    // Пишем через временный файл: обрыв записи не оставит битый JSON на сайте.
    $tmp = JSON_PATH . '.tmp';
    if (file_put_contents($tmp, $json) === false || !rename($tmp, JSON_PATH)) {
        @unlink($tmp);
        throw new RuntimeException('Не удалось записать content/photos.json — проверьте права на папку.');
    }
}

/** Принимает загруженный файл, возвращает путь вида img/beta-a1b2c3d4.jpg */
function store_upload(array $file, string $prefix): string
{
    $err = $file['error'] ?? UPLOAD_ERR_NO_FILE;
    if ($err === UPLOAD_ERR_INI_SIZE || $err === UPLOAD_ERR_FORM_SIZE) {
        throw new RuntimeException('Файл слишком большой — максимум 8 МБ.');
    }
    if ($err !== UPLOAD_ERR_OK || !is_uploaded_file($file['tmp_name'] ?? '')) {
        throw new RuntimeException('Файл не загрузился, попробуйте ещё раз.');
    }
    if (($file['size'] ?? 0) > MAX_BYTES) {
        throw new RuntimeException('Файл больше 8 МБ.');
    }
    $info = @getimagesize($file['tmp_name']);
    if (!$info || !isset(TYPES[$info[2]])) {
        throw new RuntimeException('Это не картинка. Подходят JPG, PNG и WEBP.');
    }
    if (!is_dir(IMG_DIR) && !@mkdir(IMG_DIR, 0755, true)) {
        throw new RuntimeException('Нет папки img/ и не удалось её создать.');
    }
    // Имя генерируем сами: пользовательское имя файла не участвует вообще.
    $name = $prefix . '-' . bin2hex(random_bytes(4)) . '.' . TYPES[$info[2]];
    if (!move_uploaded_file($file['tmp_name'], IMG_DIR . '/' . $name)) {
        throw new RuntimeException('Не удалось сохранить файл — проверьте права на папку img/.');
    }
    @chmod(IMG_DIR . '/' . $name, 0644);
    return 'img/' . $name;
}

/* ------------------------------------------------------------ POST-роутер */

$hash   = stored_hash();
$notice = null;
$error  = null;

try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $action = (string) ($_POST['action'] ?? '');

        if ($action === 'setup') {
            if ($hash !== null) {
                throw new RuntimeException('Пароль уже задан.');
            }
            $p1 = (string) ($_POST['pass'] ?? '');
            $p2 = (string) ($_POST['pass2'] ?? '');
            if (mb_strlen($p1) < 10) {
                throw new RuntimeException('Пароль должен быть не короче 10 символов.');
            }
            if ($p1 !== $p2) {
                throw new RuntimeException('Пароли не совпадают.');
            }
            $body = "<?php\n// Хеш пароля панели. Чтобы сбросить — удалите этот файл.\nreturn "
                . var_export(password_hash($p1, PASSWORD_DEFAULT), true) . ";\n";
            if (file_put_contents(PASS_FILE, $body) === false) {
                throw new RuntimeException('Не удалось сохранить пароль — нет прав на запись в admin/.');
            }
            @chmod(PASS_FILE, 0600);
            $hash = stored_hash();
            session_regenerate_id(true);
            $_SESSION['auth'] = true;
            $notice = 'Пароль сохранён. Запишите его — восстановить нельзя, только сбросить файлом.';
        } elseif ($action === 'login') {
            if ($hash === null) {
                throw new RuntimeException('Пароль ещё не задан.');
            }
            if (!password_verify((string) ($_POST['pass'] ?? ''), $hash)) {
                usleep(400000); // притормаживаем перебор
                throw new RuntimeException('Неверный пароль.');
            }
            session_regenerate_id(true);
            $_SESSION['auth'] = true;
            $notice = 'Готово, вы вошли.';
        } elseif ($action === 'logout') {
            $_SESSION = [];
            session_destroy();
            header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
            exit;
        } elseif (!empty($_SESSION['auth'])) {
            check_csrf();
            $data = load_data();

            if ($action === 'model') {
                $key = (string) ($_POST['key'] ?? '');
                if (!isset(MODELS[$key])) {
                    throw new RuntimeException('Неизвестная модель.');
                }
                $data['models'][$key] = store_upload($_FILES['photo'] ?? [], $key);
                save_data($data);
                $notice = 'Фото модели «' . MODELS[$key] . '» обновлено.';
            } elseif ($action === 'model_clear') {
                $key = (string) ($_POST['key'] ?? '');
                if (!isset(MODELS[$key])) {
                    throw new RuntimeException('Неизвестная модель.');
                }
                $data['models'][$key] = '';
                save_data($data);
                $notice = 'Фото модели «' . MODELS[$key] . '» убрано, стоит заглушка.';
            } elseif ($action === 'gallery_add') {
                $caption = trim((string) ($_POST['caption'] ?? ''));
                $data['gallery'][] = [
                    'image'   => store_upload($_FILES['photo'] ?? [], 'gallery'),
                    'caption' => mb_substr($caption, 0, 120),
                ];
                save_data($data);
                $notice = 'Фото добавлено в галерею.';
            } elseif ($action === 'gallery_delete') {
                $i = (int) ($_POST['index'] ?? -1);
                if (!isset($data['gallery'][$i])) {
                    throw new RuntimeException('Такого фото уже нет.');
                }
                array_splice($data['gallery'], $i, 1);
                save_data($data);
                $notice = 'Фото убрано из галереи.';
            }
        }
    }
} catch (Throwable $e) {
    $error = $e->getMessage();
}

$authed = !empty($_SESSION['auth']) && $hash !== null;
$data   = $authed ? load_data() : ['models' => [], 'gallery' => []];
$base   = '../';
?>
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Теплицы39 — управление фотографиями</title>
<style>
:root{--paper:#F3EEE4;--paper-2:#EAE2D2;--card:#FBF8F1;--ink:#20241C;--ink-2:#5B6151;
  --green:#2E6B43;--green-d:#234E32;--clay:#C6552E;--line:#DCD3BF;
  --sh:0 2px 6px rgba(32,36,28,.05),0 14px 40px rgba(32,36,28,.09)}
@media (prefers-color-scheme:dark){:root{--paper:#14160F;--paper-2:#1B1E14;--card:#1E2217;
  --ink:#ECE6D6;--ink-2:#A7AD98;--green:#5CA766;--green-d:#0F1B12;--clay:#E07A4E;--line:#2E3423;
  --sh:0 2px 8px rgba(0,0,0,.4),0 16px 44px rgba(0,0,0,.5)}}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:940px;margin:0 auto;padding:0 20px}
header{background:var(--green-d);color:#EAF0E2;padding:18px 0}
header .wrap{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
header b{font-size:1.15rem}
header a{color:#BEE0C6;margin-left:auto;font-size:.9rem}
h1{font-size:1.5rem;margin:34px 0 4px}
h2{font-size:1.15rem;margin:38px 0 4px;padding-top:20px;border-top:2px solid var(--line)}
.hint{color:var(--ink-2);font-size:.93rem;margin:6px 0 20px}
.msg{padding:14px 18px;border-radius:10px;margin:22px 0;border:1px solid var(--line);background:var(--card)}
.msg.err{border-left:4px solid var(--clay)}
.msg.ok{border-left:4px solid var(--green)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:16px;margin:0 0 10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;box-shadow:var(--sh)}
.card h3{margin:0 0 10px;font-size:1rem}
.thumb{width:100%;aspect-ratio:4/3;object-fit:cover;border-radius:10px;background:var(--paper-2);display:block}
.empty{width:100%;aspect-ratio:4/3;border-radius:10px;background:var(--paper-2);border:1px dashed var(--line);
  display:grid;place-items:center;color:var(--ink-2);font-size:.85rem}
input[type=file]{width:100%;margin:12px 0 10px;font-size:.88rem}
input[type=text],input[type=password]{width:100%;padding:11px 13px;margin:8px 0;border:1.5px solid var(--line);
  border-radius:8px;background:var(--paper);color:var(--ink);font:inherit;font-size:.95rem}
button{font:inherit;font-size:.92rem;font-weight:600;border:0;border-radius:8px;padding:10px 18px;cursor:pointer;
  background:var(--green);color:#fff}
button:hover{background:var(--green-d)}
button.ghost{background:transparent;color:var(--ink-2);border:1.5px solid var(--line)}
button.ghost:hover{background:var(--paper-2);color:var(--clay)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
form.inline{display:inline}
.cap{font-size:.9rem;color:var(--ink-2);margin:10px 0}
.login{max-width:420px;margin:60px auto;background:var(--card);border:1px solid var(--line);
  border-radius:16px;padding:30px;box-shadow:var(--sh)}
footer{color:var(--ink-2);font-size:.86rem;padding:40px 0 60px}
</style>
</head>
<body>

<header><div class="wrap">
  <b>Теплицы39 — фотографии</b>
  <?php if ($authed): ?>
    <a href="<?= h($base) ?>index.html" target="_blank" rel="noopener">Открыть сайт ↗</a>
    <form method="post" class="inline"><input type="hidden" name="action" value="logout">
      <button class="ghost" type="submit">Выйти</button></form>
  <?php endif; ?>
</div></header>

<div class="wrap">

<?php if ($error): ?><div class="msg err"><?= h($error) ?></div><?php endif; ?>
<?php if ($notice): ?><div class="msg ok"><?= h($notice) ?></div><?php endif; ?>

<?php if ($hash === null): ?>
  <div class="login">
    <h1 style="margin-top:0">Первый вход</h1>
    <p class="hint">Придумайте пароль для входа в панель — не короче 10 символов. Сделайте это прямо сейчас: пока пароль не задан, панель открыта всем.</p>
    <form method="post">
      <input type="hidden" name="action" value="setup">
      <input type="password" name="pass" placeholder="Пароль" autocomplete="new-password" required>
      <input type="password" name="pass2" placeholder="Пароль ещё раз" autocomplete="new-password" required>
      <button type="submit">Сохранить пароль</button>
    </form>
  </div>

<?php elseif (!$authed): ?>
  <div class="login">
    <h1 style="margin-top:0">Вход</h1>
    <form method="post">
      <input type="hidden" name="action" value="login">
      <input type="password" name="pass" placeholder="Пароль" autocomplete="current-password" required autofocus>
      <button type="submit">Войти</button>
    </form>
  </div>

<?php else: ?>
  <h1>Фотографии моделей</h1>
  <p class="hint">Выберите файл и нажмите «Заменить». На сайте картинка обновится сразу. Подходят JPG, PNG и WEBP до 8 МБ.</p>
  <div class="grid">
    <?php foreach (MODELS as $key => $label):
        $src = $data['models'][$key] ?? ''; ?>
      <div class="card">
        <h3><?= h($label) ?></h3>
        <?php if ($src !== ''): ?>
          <img class="thumb" src="<?= h($base . $src) ?>?t=<?= time() ?>" alt="">
        <?php else: ?>
          <div class="empty">фото нет — на сайте заглушка</div>
        <?php endif; ?>
        <form method="post" enctype="multipart/form-data" id="upl-<?= h($key) ?>">
          <input type="hidden" name="csrf" value="<?= h(csrf()) ?>">
          <input type="hidden" name="action" value="model">
          <input type="hidden" name="key" value="<?= h($key) ?>">
          <input type="file" name="photo" accept="image/jpeg,image/png,image/webp" required>
        </form>
        <div class="row">
          <button type="submit" form="upl-<?= h($key) ?>">Заменить</button>
          <?php if ($src !== ''): ?>
            <form method="post" class="inline" onsubmit="return confirm('Убрать фото этой модели?')">
              <input type="hidden" name="csrf" value="<?= h(csrf()) ?>">
              <input type="hidden" name="action" value="model_clear">
              <input type="hidden" name="key" value="<?= h($key) ?>">
              <button class="ghost" type="submit">Убрать</button>
            </form>
          <?php endif; ?>
        </div>
      </div>
    <?php endforeach; ?>
  </div>

  <h2>Галерея «Наши теплицы на участках»</h2>
  <p class="hint">Пока фотографий нет — раздел на сайте не показывается. Добавьте хотя бы одну, и он появится.</p>

  <div class="card" style="margin-bottom:20px">
    <form method="post" enctype="multipart/form-data">
      <input type="hidden" name="csrf" value="<?= h(csrf()) ?>">
      <input type="hidden" name="action" value="gallery_add">
      <input type="file" name="photo" accept="image/jpeg,image/png,image/webp" required>
      <input type="text" name="caption" maxlength="120" placeholder="Подпись, например: Прима 3 3×6, Гурьевский район (необязательно)">
      <button type="submit">Добавить в галерею</button>
    </form>
  </div>

  <?php if ($data['gallery']): ?>
    <div class="grid">
      <?php foreach ($data['gallery'] as $i => $item): ?>
        <div class="card">
          <img class="thumb" src="<?= h($base . (string) ($item['image'] ?? '')) ?>" alt="">
          <p class="cap"><?= $item['caption'] ? h((string) $item['caption']) : '<i>без подписи</i>' ?></p>
          <form method="post" onsubmit="return confirm('Удалить это фото из галереи?')">
            <input type="hidden" name="csrf" value="<?= h(csrf()) ?>">
            <input type="hidden" name="action" value="gallery_delete">
            <input type="hidden" name="index" value="<?= (int) $i ?>">
            <button class="ghost" type="submit">Удалить</button>
          </form>
        </div>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>
<?php endif; ?>

<footer>Теплицы39 · панель управления фотографиями</footer>
</div>
</body>
</html>
