import 'package:coinslib/bech32/bech32.dart';
import 'package:test/test.dart';

void main() {
  group('bech32 with', () {
    group('valid test vectors from specification', () {
      [
        'A12UEL5L',
        'a12uel5l',
        'an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs',
        'abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw',
        '11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j',
        'split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w',
        '?1ezyfcl',
      ]
        ..forEach((vec) {
          test('decode static vector: $vec', () {
            expect(bech32.decode(vec), isNotNull);
          });
        })
        ..forEach((vec) {
          test('decode then encode static vector: $vec', () {
            expect(bech32.encode(bech32.decode(vec)), vec.toLowerCase());
          });
        });

      [
        'lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w',
        'lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpuaztrnwngzn3kdzw5hydlzf03qdgm2hdq27cqv3agm2awhz5se903vruatfhq77w3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rspfj9srp',
        'lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqscc6gd6ql3jrc5yzme8v4ntcewwz5cnw92tz0pc8qcuufvq7khhr8wpald05e92xw006sq94mg8v2ndf4sefvf9sygkshp5zfem29trqq2yxxz7',
        'lntb20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un98kmzzhznpurw9sgl2v0nklu2g4d0keph5t7tj9tcqd8rexnd07ux4uv2cjvcqwaxgj7v4uwn5wmypjd5n69z2xm3xgksg28nwht7f6zspwp3f9t',
        'lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqj9n4evl6mr5aj9f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qqdhhwkj',
        'lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdees9q4pqqqqqqqqqqqqqqqqqqszk3ed62snp73037h4py4gry05eltlp0uezm2w9ajnerhmxzhzhsu40g9mgyx5v3ad4aqwkmvyftzk4k9zenz90mhjcy9hcevc7r3lx2sphzfxz7',
      ]
        ..forEach((req) {
          test('decode BOLT11 String: ${req.substring(0, 90)}...', () {
            expect(bech32.decode(req, req.length), isNotNull);
          });
        })
        ..forEach((req) {
          test('decode then encode BOLT11 String: ${req.substring(0, 90)}...',
              () {
            var l = req.length;
            expect(
              bech32.encode(bech32.decode(req, l), l),
              req.toLowerCase(),
            );
          });
        });
    });

    group('invalid test vectors from specification having', () {
      test('hrp character out of range (space char)', () {
        expect(() => bech32.decode('\x20' '1nwldj5'),
            throwsA(TypeMatcher<OutOfRangeHrpCharacters>()));
      });

      test('hrp character out of range (delete char)', () {
        expect(() => bech32.decode('\x7F' '1axkwrx'),
            throwsA(TypeMatcher<OutOfRangeHrpCharacters>()));
      });

      test('hrp character out of range (control char)', () {
        expect(() => bech32.decode('\x80' '1eym55h'),
            throwsA(TypeMatcher<OutOfRangeHrpCharacters>()));
      });

      test('too long overall', () {
        expect(
            () => bech32.decode(
                'an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx'),
            throwsA(TypeMatcher<TooLong>()));
      });

      test('no separator', () {
        expect(() => bech32.decode('pzry9x0s0muk'),
            throwsA(TypeMatcher<InvalidSeparator>()));
      });

      test('empty hpr', () {
        expect(() => bech32.decode('1pzry9x0s0muk'),
            throwsA(TypeMatcher<TooShortHrp>()));
      });

      test('invalid data character', () {
        expect(() => bech32.decode('x1b4n0q5v'),
            throwsA(TypeMatcher<OutOfBoundChars>()));
      });

      test('too short checksum', () {
        expect(() => bech32.decode('li1dgmt3'),
            throwsA(TypeMatcher<TooShortChecksum>()));
      });

      test('invalid checksum character', () {
        expect(() => bech32.decode('de1lg7wt' '\xFF'),
            throwsA(TypeMatcher<OutOfBoundChars>()));
      });

      test('checksum calculated from upper case hpr', () {
        expect(() => bech32.decode('A1G7SGD8'),
            throwsA(TypeMatcher<InvalidChecksum>()));
      });

      test('empty hpr, case one', () {
        expect(() => bech32.decode('10a06t8'),
            throwsA(TypeMatcher<TooShortHrp>()));
      });

      test('empty hpr, case two', () {
        expect(() => bech32.decode('1qzzfhee'),
            throwsA(TypeMatcher<TooShortHrp>()));
      });
    });

    group('length override', () {
      test('valid maxLength parameter', () {
        var str =
            'lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w';
        expect(() => bech32.decode(str, str.length + 5), isNotNull);
      });

      test('invalid maxLength parameter', () {
        var str =
            'lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w';
        expect(() => bech32.decode(str, str.length - 5),
            throwsA(TypeMatcher<TooLong>()));
      });
    });
  });
}
