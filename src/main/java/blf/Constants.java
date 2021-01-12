package blf;

import blf.blockchains.hyperledger.HyperledgerListener;
import blf.configuration.BaseBlockchainListener;
import blf.blockchains.ethereum.EthereumListener;
import blf.parsing.VariableExistenceListener;

import java.util.HashMap;
import java.util.Map;

public class Constants {

    public static final String ETHEREUM_BLOCKCHAIN_KEY = "ethereum";
    public static final String HYPERLEDGER_BLOCKCHAIN_KEY = "hyperledger";

    private static final Map<String, BaseBlockchainListener> blockchainMap = new HashMap<>();

    public static Map<String, BaseBlockchainListener> getBlockchainMap(VariableExistenceListener variableExistenceListener) {
        blockchainMap.put(ETHEREUM_BLOCKCHAIN_KEY, new EthereumListener(variableExistenceListener));
        blockchainMap.put(HYPERLEDGER_BLOCKCHAIN_KEY, new HyperledgerListener(variableExistenceListener));

        return blockchainMap;
    }

}
