
// Description: Java 25 in-memory RAM DbIO implementation for SecUserPassword.

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;

import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecUserPasswordTable in-memory RAM DbIO implementation
 *	for SecUserPassword.
 */
public class CFSecRamSecUserPasswordTable
	implements ICFSecSecUserPasswordTable
{
	private ICFSecSchema schema;
	private Map< ICFLibKeyHash256,
				CFSecBuffSecUserPassword > dictByPKey
		= new HashMap< ICFLibKeyHash256,
				CFSecBuffSecUserPassword >();
	private Map< CFSecBuffSecUserPasswordBySetStampIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecUserPassword >> dictBySetStampIdx
		= new HashMap< CFSecBuffSecUserPasswordBySetStampIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecUserPassword >>();

	public CFSecRamSecUserPasswordTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecUserPassword ensureRec(ICFSecSecUserPassword rec) {
		return (((CFSecBuffSecUserPasswordFactoryService)(schema.getCFSecBuffFactory().getFactorySecUserPassword())).ensureRec(rec));
	}

	@Override
	public ICFSecSecUserPassword createSecUserPassword( ICFSecAuthorization Authorization,
		ICFSecSecUserPassword iBuff )
	{
		final String S_ProcName = "createSecUserPassword";
		
		CFSecBuffSecUserPassword Buff = (CFSecBuffSecUserPassword)ensureRec(iBuff);
		ICFLibKeyHash256 pkey;
		pkey = Buff.getRequiredSecUserId();
		pkey = Buff.getRequiredSecUserId();
		Buff.setRequiredContainerUser( pkey );
		Buff.setRequiredSecUserId( pkey );
		CFSecBuffSecUserPasswordBySetStampIdxKey keySetStampIdx = (CFSecBuffSecUserPasswordBySetStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPassword().newBySetStampIdxKey();
		keySetStampIdx.setRequiredPWSetStamp( Buff.getRequiredPWSetStamp() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableSecUser().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecUserId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"Container",
						"SecUser",
						"SecUser",
						"SecUser",
						"SecUser",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< ICFLibKeyHash256, CFSecBuffSecUserPassword > subdictSetStampIdx;
		if( dictBySetStampIdx.containsKey( keySetStampIdx ) ) {
			subdictSetStampIdx = dictBySetStampIdx.get( keySetStampIdx );
		}
		else {
			subdictSetStampIdx = new HashMap< ICFLibKeyHash256, CFSecBuffSecUserPassword >();
			dictBySetStampIdx.put( keySetStampIdx, subdictSetStampIdx );
		}
		subdictSetStampIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecUserPassword.CLASS_CODE) {
				CFSecBuffSecUserPassword retbuff = ((CFSecBuffSecUserPassword)(schema.getCFSecBuffFactory().getFactorySecUserPassword().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecUserPassword readDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecUserPassword.readDerived";
		ICFSecSecUserPassword buff;
		if( PKey == null ) {
			return( null );
		}
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserPassword lockDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecUserPassword.lockDerived";
		ICFSecSecUserPassword buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserPassword[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecUserPassword.readAllDerived";
		ICFSecSecUserPassword[] retList = new ICFSecSecUserPassword[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecUserPassword > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecUserPassword[] readDerivedBySetStampIdx( ICFSecAuthorization Authorization,
		LocalDateTime PWSetStamp )
	{
		final String S_ProcName = "CFSecRamSecUserPassword.readDerivedBySetStampIdx";
		CFSecBuffSecUserPasswordBySetStampIdxKey key = (CFSecBuffSecUserPasswordBySetStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPassword().newBySetStampIdxKey();

		key.setRequiredPWSetStamp( PWSetStamp );
		ICFSecSecUserPassword[] recArray;
		if( dictBySetStampIdx.containsKey( key ) ) {
			Map< ICFLibKeyHash256, CFSecBuffSecUserPassword > subdictSetStampIdx
				= dictBySetStampIdx.get( key );
			recArray = new ICFSecSecUserPassword[ subdictSetStampIdx.size() ];
			Iterator< CFSecBuffSecUserPassword > iter = subdictSetStampIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< ICFLibKeyHash256, CFSecBuffSecUserPassword > subdictSetStampIdx
				= new HashMap< ICFLibKeyHash256, CFSecBuffSecUserPassword >();
			dictBySetStampIdx.put( key, subdictSetStampIdx );
			recArray = new ICFSecSecUserPassword[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecUserPassword readDerivedByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecUserPassword.readDerivedByIdIdx() ";
		ICFSecSecUserPassword buff;
		if( dictByPKey.containsKey( SecUserId ) ) {
			buff = dictByPKey.get( SecUserId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserPassword readRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecUserPassword.readRec";
		ICFSecSecUserPassword buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecUserPassword.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserPassword lockRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecUserPassword buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecUserPassword.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserPassword[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecUserPassword.readAllRec";
		ICFSecSecUserPassword buff;
		ArrayList<ICFSecSecUserPassword> filteredList = new ArrayList<ICFSecSecUserPassword>();
		ICFSecSecUserPassword[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUserPassword.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUserPassword[0] ) );
	}

	@Override
	public ICFSecSecUserPassword readRecByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecUserPassword.readRecByIdIdx() ";
		ICFSecSecUserPassword buff = readDerivedByIdIdx( Authorization,
			SecUserId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUserPassword.CLASS_CODE ) ) {
			return( (ICFSecSecUserPassword)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecUserPassword[] readRecBySetStampIdx( ICFSecAuthorization Authorization,
		LocalDateTime PWSetStamp )
	{
		final String S_ProcName = "CFSecRamSecUserPassword.readRecBySetStampIdx() ";
		ICFSecSecUserPassword buff;
		ArrayList<ICFSecSecUserPassword> filteredList = new ArrayList<ICFSecSecUserPassword>();
		ICFSecSecUserPassword[] buffList = readDerivedBySetStampIdx( Authorization,
			PWSetStamp );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUserPassword.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecUserPassword)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUserPassword[0] ) );
	}

	public ICFSecSecUserPassword updateSecUserPassword( ICFSecAuthorization Authorization,
		ICFSecSecUserPassword iBuff )
	{
		CFSecBuffSecUserPassword Buff = (CFSecBuffSecUserPassword)ensureRec(iBuff);
		ICFLibKeyHash256 pkey = (ICFLibKeyHash256)Buff.getPKey();
		CFSecBuffSecUserPassword existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecUserPassword",
				"Existing record not found",
				"Existing record not found",
				"SecUserPassword",
				"SecUserPassword",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecUserPassword",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecUserPasswordBySetStampIdxKey existingKeySetStampIdx = (CFSecBuffSecUserPasswordBySetStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPassword().newBySetStampIdxKey();
		existingKeySetStampIdx.setRequiredPWSetStamp( existing.getRequiredPWSetStamp() );

		CFSecBuffSecUserPasswordBySetStampIdxKey newKeySetStampIdx = (CFSecBuffSecUserPasswordBySetStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPassword().newBySetStampIdxKey();
		newKeySetStampIdx.setRequiredPWSetStamp( Buff.getRequiredPWSetStamp() );

		// Check unique indexes

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecUser().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecUserId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecUserPassword",
						"Container",
						"Container",
						"SecUser",
						"SecUser",
						"SecUser",
						"SecUser",
						null );
				}
			}
		}

		// Update is valid

		Map< ICFLibKeyHash256, CFSecBuffSecUserPassword > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictBySetStampIdx.get( existingKeySetStampIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictBySetStampIdx.containsKey( newKeySetStampIdx ) ) {
			subdict = dictBySetStampIdx.get( newKeySetStampIdx );
		}
		else {
			subdict = new HashMap< ICFLibKeyHash256, CFSecBuffSecUserPassword >();
			dictBySetStampIdx.put( newKeySetStampIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecUserPassword( ICFSecAuthorization Authorization,
		ICFSecSecUserPassword iBuff )
	{
		final String S_ProcName = "CFSecRamSecUserPasswordTable.deleteSecUserPassword() ";
		CFSecBuffSecUserPassword Buff = (CFSecBuffSecUserPassword)ensureRec(iBuff);
		int classCode;
		ICFLibKeyHash256 pkey = (ICFLibKeyHash256)(Buff.getPKey());
		CFSecBuffSecUserPassword existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecUserPassword",
				pkey );
		}
		CFSecBuffSecUserPasswordBySetStampIdxKey keySetStampIdx = (CFSecBuffSecUserPasswordBySetStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPassword().newBySetStampIdxKey();
		keySetStampIdx.setRequiredPWSetStamp( existing.getRequiredPWSetStamp() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< ICFLibKeyHash256, CFSecBuffSecUserPassword > subdict;

		dictByPKey.remove( pkey );

		subdict = dictBySetStampIdx.get( keySetStampIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecUserPasswordByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecUserPassword cur;
		LinkedList<CFSecBuffSecUserPassword> matchSet = new LinkedList<CFSecBuffSecUserPassword>();
		Iterator<CFSecBuffSecUserPassword> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUserPassword> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUserPassword)(schema.getTableSecUserPassword().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() ));
			deleteSecUserPassword( Authorization, cur );
		}
	}

	@Override
	public void deleteSecUserPasswordBySetStampIdx( ICFSecAuthorization Authorization,
		LocalDateTime argPWSetStamp )
	{
		CFSecBuffSecUserPasswordBySetStampIdxKey key = (CFSecBuffSecUserPasswordBySetStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPassword().newBySetStampIdxKey();
		key.setRequiredPWSetStamp( argPWSetStamp );
		deleteSecUserPasswordBySetStampIdx( Authorization, key );
	}

	@Override
	public void deleteSecUserPasswordBySetStampIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserPasswordBySetStampIdxKey argKey )
	{
		CFSecBuffSecUserPassword cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecUserPassword> matchSet = new LinkedList<CFSecBuffSecUserPassword>();
		Iterator<CFSecBuffSecUserPassword> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUserPassword> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUserPassword)(schema.getTableSecUserPassword().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() ));
			deleteSecUserPassword( Authorization, cur );
		}
	}
}
