import sys
if len(sys.argv) < 2:
    print('NO ARGV')
else:
    a = sys.argv[1]
    print('REPR:', repr(a))
    print('LEN:', len(a))
    print('STARTS:', a[:5])
    print('ENDS:', a[-5:])
