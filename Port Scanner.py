import nmap
import optparse
def nmapscan(taghost,tagport):
    nmscan=nmap.PortScanner()
    nmscan.scan(taghost,tagport)
    state=nmscan[tgthost]['tcp'][int(tagport)]['state']
    print('[*] ' + tgthost + 'tcp' + tagport + state)
def main():
    parser=optparse.OptionParser('usage%prog' + '-H <target host> -P <target port>')
    parser.add_option('-H' , dest='tgthost' , type='string' , help='specify target host')
    parser.add_option('-p', dest='tgtport', type='string', help='specify target ports')
    (options,args)=parser.parse_args()
    tgthost=options.tgthost
    tgtport=str(options.tgtport).split(' , ')
    if (tgthost==None ) | (tgtport[0] == None):
        print(parser.usage)
        exit(0)
        for tgtport in tgtports:
            nmapscan(tgthost,tgtport)
if __name__ =='__main__':
    main()