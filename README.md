## Desciption

Based on [Kasper](https://code.google.com/archive/p/kasper/) but in [v language](https://vlang.io/). Mostly rewritten using [The unarchiver](https://theunarchiver.com/) as the base.

## Usage

Check out project:

```
git checkout git@github.com:mecolosimo/kasperv.git
cd kasperv
```

Buiding is easy:

```bash
v .
```

Running on all ASCII four letter passords ending with```oly```:

```bash
./kasperv -p*oly -sexamples/holy.sit -w
./kasperv -p*oly -sexamples/holy_dlx3.0.7.sit -w
 ```

Using a word list with 2 threads

```bash
./kasperv -fexamples/wordlist.txt  -sexamples/holy.sit -n 2
```
